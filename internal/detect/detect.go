package detect

import (
	"bytes"
	"compress/zlib"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"regexp"
	"strings"
)

// DetectionDetail captures stream-level findings.
type DetectionDetail struct {
	StreamName string
	RiskLevel  string
	Reason     string
	HexDump    string
}

// MaxDecompressSize limits decompression to avoid zip bombs.
const MaxDecompressSize = 10 * 1024 * 1024

// 악성 링크 패턴 정의 (Javascript, VBScript, File URI, Powershell 등)
var suspiciousLinkRegex = regexp.MustCompile(`(?i)(javascript:|vbscript:|file://|powershell:|cmd:|/bin/sh)`)

func calculateEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	freq := make(map[byte]int)
	for _, b := range data {
		freq[b]++
	}
	var entropy float64
	total := float64(len(data))
	for _, count := range freq {
		p := float64(count) / total
		entropy -= p * math.Log2(p)
	}
	return entropy
}

func tryDecompress(data []byte) []byte {
	if len(data) < 10 {
		return nil
	}
	defer func() {
		if r := recover(); r != nil {
		}
	}()

	b := bytes.NewReader(data)
	r, err := zlib.NewReader(b)
	if err != nil {
		return nil
	}
	defer r.Close()

	limitReader := io.LimitReader(r, MaxDecompressSize)
	decompressed, err := io.ReadAll(limitReader)
	if err != nil {
		return nil
	}
	return decompressed
}

func isPEHeader(data []byte) bool {
	if len(data) < 2 {
		return false
	}
	return data[0] == 0x4D && data[1] == 0x5A // "MZ"
}

func hasImageSignature(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	scanLimit := 512
	if len(data) < scanLimit {
		scanLimit = len(data)
	}
	headerArea := data[:scanLimit]

	signatures := [][]byte{
		{0xFF, 0xD8, 0xFF},       // JPG
		{0x89, 0x50, 0x4E, 0x47}, // PNG
		{0x47, 0x49, 0x46, 0x38}, // GIF
		{0x42, 0x4D},             // BMP
		{0xD7, 0xCD, 0xC6, 0x9A}, // WMF
	}

	for _, sig := range signatures {
		if bytes.Contains(headerArea, sig) {
			return true
		}
	}
	return false
}

// CheckStreamContent inspects the provided stream content and returns a finding when suspicious patterns appear.
func CheckStreamContent(name string, data []byte) *DetectionDetail {
	entropy := calculateEntropy(data)
	lowerName := strings.ToLower(name)

	headerHex := ""
	if len(data) >= 16 {
		headerHex = hex.EncodeToString(data[:16])
	} else {
		headerHex = hex.EncodeToString(data)
	}

	// 1. 실행 파일(PE) 헤더 은닉 여부
	if isPEHeader(data) {
		return &DetectionDetail{
			StreamName: name,
			RiskLevel:  "CRITICAL",
			Reason:     "실행 파일(PE/DLL - MZ Header) 은닉 발견",
			HexDump:    headerHex,
		}
	}

	decompressed := tryDecompress(data)
	if decompressed != nil {
		if isPEHeader(decompressed) {
			return &DetectionDetail{
				StreamName: name,
				RiskLevel:  "CRITICAL",
				Reason:     "압축 해제된 데이터 내부에서 실행 파일 발견",
				HexDump:    hex.EncodeToString(decompressed[:16]),
			}
		}
	}

	// 2. 이미지 위변조 검사 (File Extension Spoofing 방어)
	isImageExt := strings.HasSuffix(lowerName, ".jpg") || strings.HasSuffix(lowerName, ".jpeg") ||
		strings.HasSuffix(lowerName, ".png") || strings.HasSuffix(lowerName, ".gif") ||
		strings.HasSuffix(lowerName, ".bmp") || strings.HasSuffix(lowerName, ".wmf")

	if isImageExt {
		hasSignature := hasImageSignature(data)
		if !hasSignature && decompressed != nil {
			hasSignature = hasImageSignature(decompressed)
		}

		if !hasSignature {
			// 시그니처가 없으면 스크립트인지 재확인
			isScript := bytes.Contains(data, []byte("JScript")) ||
				bytes.Contains(data, []byte("Javascript")) ||
				bytes.Contains(data, []byte("powershell"))

			if isScript {
				return &DetectionDetail{
					StreamName: name,
					RiskLevel:  "CRITICAL",
					Reason:     "이미지로 위장된 악성 스크립트(JScript/PowerShell) 발견",
					HexDump:    headerHex,
				}
			}

			// 안전한 비표준 이미지
			return &DetectionDetail{
				StreamName: name,
				RiskLevel:  "INFO",
				Reason:     "비표준 이미지 포맷 (특이사항 없음)",
				HexDump:    headerHex,
			}
		}
	}

	// 3. 엔트로피 및 DLL 검사
	if entropy > 7.8 {
		// [수정됨] HWP 표준 스트림 이름들을 안전 목록에 추가하여 오탐 방지
		safeKeywords := []string{
			"section",     // 본문 섹션
			"bindata",     // 첨부 데이터
			"prvtext",     // 미리보기 텍스트
			"prvimage",    // 미리보기 이미지
			"docinfo",     // 문서 정보 (오탐 원인 해결)
			"bodytext",    // 본문 텍스트
			"fileheader",  // 파일 헤더
			"summaryinfo", // 요약 정보
		}

		isSafeContext := isImageExt
		for _, k := range safeKeywords {
			if strings.Contains(lowerName, k) {
				isSafeContext = true
				break
			}
		}

		// 안전한 키워드에 포함되지 않는 경우에만 경고
		if !isSafeContext {
			return &DetectionDetail{
				StreamName: name,
				RiskLevel:  "WARNING",
				Reason:     fmt.Sprintf("알 수 없는 고밀도 데이터 (Shellcode 의심, Entropy: %.2f)", entropy),
				HexDump:    headerHex,
			}
		}
	} else if entropy > 7.0 && strings.Contains(lowerName, ".dll") {
		return &DetectionDetail{
			StreamName: name,
			RiskLevel:  "WARNING",
			Reason:     fmt.Sprintf("의심스러운 DLL 파일 (Entropy: %.2f)", entropy),
			HexDump:    headerHex,
		}
	}

	// 4. 취약점 탐지 (EPS, Script)
	if bytes.HasPrefix(data, []byte("%!")) || strings.HasSuffix(lowerName, ".eps") {
		return &DetectionDetail{
			StreamName: name,
			RiskLevel:  "CRITICAL",
			Reason:     "EPS(PostScript) 취약점 벡터 발견",
			HexDump:    headerHex,
		}
	}

	if bytes.Contains(data, []byte("JScript")) || bytes.Contains(data, []byte("Javascript")) || bytes.Contains(data, []byte("powershell")) {
		return &DetectionDetail{
			StreamName: name,
			RiskLevel:  "CRITICAL",
			Reason:     "스크립트 실행 코드 패턴 발견",
			HexDump:    headerHex,
		}
	}

	// 5. 악성 링크 및 커맨드 패턴 (Invalid href 탐지)
	scanLimit := 1024 * 1024
	scanData := data
	if len(data) > scanLimit {
		scanData = data[:scanLimit]
	}

	if suspiciousLinkRegex.Match(scanData) {
		// []byte를 string으로 변환
		found := string(suspiciousLinkRegex.Find(scanData))

		if len(found) > 50 {
			found = found[:47] + "..."
		}
		return &DetectionDetail{
			StreamName: name,
			RiskLevel:  "CRITICAL",
			Reason:     fmt.Sprintf("악성 링크/커맨드 패턴 발견 (%s)", found),
			HexDump:    headerHex,
		}
	}

	return nil
}
