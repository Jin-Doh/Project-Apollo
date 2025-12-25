package report

import (
	"archive/zip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAnalyzeFile_HWPXDetects(t *testing.T) {
	tmpDir := t.TempDir()
	zipPath := filepath.Join(tmpDir, "sample.hwp.x")

	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatalf("create zip: %v", err)
	}
	zw := zip.NewWriter(f)

	w, err := zw.Create("BinData/evil.exe")
	if err != nil {
		t.Fatalf("create entry: %v", err)
	}
	_, err = w.Write([]byte{0x4D, 0x5A, 0x00})
	if err != nil {
		t.Fatalf("write entry: %v", err)
	}
	zw.Close()
	f.Close()

	out := AnalyzeFile(zipPath)
	if !strings.Contains(out, "🔴 결과") && !strings.Contains(out, "위험") {
		t.Fatalf("expected report to indicate risk, got:\n%s", out)
	}
}
