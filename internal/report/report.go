package report

import (
	"fmt"
	"os"
	"strings"
	"time"

	"project_apollo/internal/detect"
	"project_apollo/internal/scan"
)

// AnalyzeFile produces a human-readable report for the given file path.
func AnalyzeFile(filePath string) string {
	var sb strings.Builder

	// 리포트 헤더 작성
	sb.WriteString("==================================================\n")
	sb.WriteString("[ HWP 보안 위협 분석 리포트 ]\n")
	sb.WriteString(fmt.Sprintf("분석 일시: %s\n", time.Now().Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("파일 경로: %s\n", filePath))
	sb.WriteString("==================================================\n\n")

	// 파일 열기
	file, err := os.Open(filePath)
	if err != nil {
		return "오류: 파일을 읽을 수 없습니다.\n"
	}

	// 파일 크기 확인
	stat, _ := file.Stat()
	sb.WriteString(fmt.Sprintf("파일 크기: %d bytes\n", stat.Size()))

	// 헤더 확인 (HWP vs HWPX 구분)
	header := make([]byte, 4)
	n, err := file.Read(header)
	if err != nil || n < 2 {
		file.Close()
		return "오류: 파일이 손상되었거나 읽을 수 없습니다.\n"
	}

	isHWPX := string(header[:2]) == "PK"
	file.Seek(0, 0) // 파일 포인터 초기화

	var detections []detect.DetectionDetail
	var scanErr error

	// 포맷별 스캔 실행
	if isHWPX {
		sb.WriteString("파일 포맷: HWPX (Open XML / ZIP 기반)\n\n")
		file.Close() // HWPX는 zip.OpenReader(path)를 사용하므로 파일 핸들 닫음
		detections, scanErr = scan.ScanHWPX(filePath)
	} else {
		sb.WriteString("파일 포맷: HWP (OLE / Compound File 기반)\n\n")
		detections, scanErr = scan.ScanHWP(file)
		file.Close()
	}

	if scanErr != nil {
		sb.WriteString(fmt.Sprintf("분석 중 오류 발생: %v\n", scanErr))
		return sb.String()
	}

	// 탐지 결과 집계
	criticalCount := 0
	warningCount := 0

	sb.WriteString("[ 상세 분석 결과 ]\n")
	if len(detections) == 0 {
		sb.WriteString("- 특이사항 없음. (내부 스트림 검사 완료)\n")
	} else {
		for _, d := range detections {
			if d.RiskLevel == "CRITICAL" {
				criticalCount++
			}
			if d.RiskLevel == "WARNING" {
				warningCount++
			}

			// 단순 정보(INFO)는 요약 출력 후 스킵
			if d.RiskLevel == "INFO" {
				sb.WriteString(fmt.Sprintf("[정보] %s: %s\n", d.StreamName, d.Reason))
				continue
			}

			// 상세 내용 출력
			sb.WriteString("--------------------------------------------------\n")
			sb.WriteString(fmt.Sprintf("🚩 탐지 항목: %s\n", d.StreamName))
			sb.WriteString(fmt.Sprintf("   - 위험도: %s\n", d.RiskLevel))
			sb.WriteString(fmt.Sprintf("   - 진단명: %s\n", d.Reason))
			sb.WriteString(fmt.Sprintf("   - 증거 데이터(Hex): %s...\n", d.HexDump))
		}
		sb.WriteString("--------------------------------------------------\n\n")
	}

	// 최종 판정
	sb.WriteString("[ 최종 판정 ]\n")
	if criticalCount > 0 {
		sb.WriteString("🔴 결과: [위험] 악성 코드가 의심되는 요소가 발견되었습니다.\n")
		sb.WriteString("   -> 조치: 즉시 파일을 격리하고 본 리포트를 보안담당자에게 전달하십시오.\n")
	} else if warningCount > 0 {
		sb.WriteString("🟡 결과: [주의] 비정상적인 구조가 발견되었습니다.\n")
		sb.WriteString("   -> 조치: 신뢰할 수 없는 출처라면 실행하지 마십시오.\n")
	} else {
		sb.WriteString("🟢 결과: [안전] 알려진 위협 요소가 발견되지 않았습니다.\n")
	}

	return sb.String()
}
