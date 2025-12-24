package scan

import (
	"archive/zip"
	"io"
	"os"
	"strings"

	"project_apollo/internal/detect"

	"github.com/richardlehane/mscfb"
)

// ScanHWP inspects streams within a legacy HWP file.
func ScanHWP(file *os.File) ([]detect.DetectionDetail, error) {
	doc, err := mscfb.New(file)
	if err != nil {
		return nil, err
	}

	var detections []detect.DetectionDetail
	for entry, err := doc.Next(); err == nil; entry, err = doc.Next() {
		buf := make([]byte, entry.Size)
		_, err := doc.Read(buf)
		if err != nil {
			continue
		}
		if detail := detect.CheckStreamContent(entry.Name, buf); detail != nil {
			detections = append(detections, *detail)
		}
	}
	return detections, nil
}

// ScanHWPX inspects streams within an HWPX (ZIP-based) file.
func ScanHWPX(path string) ([]detect.DetectionDetail, error) {
	r, err := zip.OpenReader(path)
	if err != nil {
		return nil, err
	}
	defer r.Close()

	var detections []detect.DetectionDetail
	for _, f := range r.File {
		// 검사 속도 최적화를 위한 필터링
		if !strings.Contains(f.Name, "BinData") &&
			!strings.HasSuffix(f.Name, ".exe") &&
			!strings.HasSuffix(f.Name, ".dll") &&
			!strings.HasSuffix(f.Name, ".eps") {
			continue
		}

		rc, err := f.Open()
		if err != nil {
			continue
		}

		// [보안] Zip Bomb 방지: LimitReader 적용 (detect 패키지의 상수 사용)
		limitReader := io.LimitReader(rc, detect.MaxDecompressSize)
		buf, err := io.ReadAll(limitReader)
		rc.Close()

		// 용량 초과 에러(EOF 등)는 무시하고 읽은 만큼만 검사 진행
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			continue
		}

		if detail := detect.CheckStreamContent(f.Name, buf); detail != nil {
			detections = append(detections, *detail)
		}
	}
	return detections, nil
}
