package scan

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"

	"project_apollo/internal/detect"
)

func TestScanHWPX_DetectsPEInZip(t *testing.T) {
	tmpDir := t.TempDir()
	zipPath := filepath.Join(tmpDir, "test.hwp.x")

	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatalf("create zip file: %v", err)
	}
	zw := zip.NewWriter(f)

	// Add a BinData file that contains an MZ header
	w, err := zw.Create("BinData/evil.exe")
	if err != nil {
		t.Fatalf("create entry: %v", err)
	}
	_, err = w.Write([]byte{0x4D, 0x5A, 0x00, 0x00})
	if err != nil {
		t.Fatalf("write entry: %v", err)
	}

	zw.Close()
	f.Close()

	detections, err := ScanHWPX(zipPath)
	if err != nil {
		t.Fatalf("ScanHWPX returned error: %v", err)
	}
	if len(detections) == 0 {
		t.Fatalf("expected detections for embedded PE, got none")
	}
}

func TestScanHWPX_SkipsNonMatching(t *testing.T) {
	tmpDir := t.TempDir()
	zipPath := filepath.Join(tmpDir, "test2.hwp.x")

	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatalf("create zip file: %v", err)
	}
	zw := zip.NewWriter(f)

	// Add a non-matching file name
	w, err := zw.Create("doc/content.xml")
	if err != nil {
		t.Fatalf("create entry: %v", err)
	}
	_, err = w.Write([]byte("<xml/>"))
	if err != nil {
		t.Fatalf("write entry: %v", err)
	}

	zw.Close()
	f.Close()

	detections, err := ScanHWPX(zipPath)
	if err != nil {
		t.Fatalf("ScanHWPX returned error: %v", err)
	}
	if len(detections) != 0 {
		t.Fatalf("expected no detections for non-matching entries, got %d", len(detections))
	}
}

func TestScanHWPX_LargeEntry_ReadLimited(t *testing.T) {
	tmpDir := t.TempDir()
	zipPath := filepath.Join(tmpDir, "large.hwp.x")

	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatalf("create zip file: %v", err)
	}
	zw := zip.NewWriter(f)

	// Create BinData/huge.bin with size larger than MaxDecompressSize to ensure LimitReader is used
	w, err := zw.Create("BinData/huge.bin")
	if err != nil {
		t.Fatalf("create entry: %v", err)
	}

	huge := make([]byte, detect.MaxDecompressSize+1024)
	// fill with repeating pattern
	for i := range huge {
		huge[i] = byte(i % 256)
	}

	if _, err := w.Write(huge); err != nil {
		t.Fatalf("write huge entry: %v", err)
	}

	zw.Close()
	f.Close()

	// Should not panic and should return either 0 or more detections depending on entropy logic
	_, err = ScanHWPX(zipPath)
	if err != nil {
		t.Fatalf("ScanHWPX returned error on large entry: %v", err)
	}
}

func TestScanHWPX_ProcessesDllSuffix(t *testing.T) {
	tmpDir := t.TempDir()
	zipPath := filepath.Join(tmpDir, "dll.hwp.x")

	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatalf("create zip file: %v", err)
	}
	zw := zip.NewWriter(f)

	// Add a plugin.dll outside BinData but matching suffix
	w, err := zw.Create("somepath/plugin.dll")
	if err != nil {
		t.Fatalf("create entry: %v", err)
	}
	_, err = w.Write([]byte{0x4D, 0x5A, 0x00})
	if err != nil {
		t.Fatalf("write entry: %v", err)
	}

	zw.Close()
	f.Close()

	detections, err := ScanHWPX(zipPath)
	if err != nil {
		t.Fatalf("ScanHWPX returned error: %v", err)
	}
	if len(detections) == 0 {
		t.Fatalf("expected detection for plugin.dll, got none")
	}
}
