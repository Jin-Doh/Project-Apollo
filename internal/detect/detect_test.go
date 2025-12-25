package detect

import (
	"bytes"
	"compress/zlib"
	"testing"
)

func TestCalculateEntropyEmpty(t *testing.T) {
	if e := calculateEntropy([]byte{}); e != 0 {
		t.Fatalf("expected 0 entropy for empty slice, got %f", e)
	}
}

func TestCalculateEntropyNonZero(t *testing.T) {
	data := []byte{0, 1, 2, 3, 4, 5, 6, 7}
	if e := calculateEntropy(data); e <= 0 {
		t.Fatalf("expected entropy > 0, got %f", e)
	}
}

func TestIsPEHeader(t *testing.T) {
	data := []byte{0x4D, 0x5A, 0x00}
	if !isPEHeader(data) {
		t.Fatalf("expected PE header detection")
	}
}

func TestHasImageSignature(t *testing.T) {
	png := []byte{0x89, 0x50, 0x4E, 0x47, 0x00}
	if !hasImageSignature(png) {
		t.Fatalf("expected PNG signature to be detected")
	}

	random := []byte{0x01, 0x02, 0x03, 0x04}
	if hasImageSignature(random) {
		t.Fatalf("did not expect random bytes to be detected as image")
	}
}

func TestTryDecompress(t *testing.T) {
	var b bytes.Buffer
	w := zlib.NewWriter(&b)
	orig := []byte("hello compressed world")
	if _, err := w.Write(orig); err != nil {
		t.Fatalf("failed to compress: %v", err)
	}
	w.Close()

	out := tryDecompress(b.Bytes())
	if out == nil {
		t.Fatalf("expected decompressed output, got nil")
	}
	if string(out) != string(orig) {
		t.Fatalf("decompressed content mismatch: %s", string(out))
	}
}

func TestCheckStreamContent_PE(t *testing.T) {
	detail := CheckStreamContent("evil.exe", []byte{0x4D, 0x5A, 0x90})
	if detail == nil {
		t.Fatalf("expected detection for PE header")
	}
	if detail.RiskLevel != "CRITICAL" {
		t.Fatalf("expected CRITICAL risk, got %s", detail.RiskLevel)
	}
}

func TestCheckStreamContent_DecompressedPE(t *testing.T) {
	// compress an MZ header so CheckStreamContent finds it after decompression
	var b bytes.Buffer
	w := zlib.NewWriter(&b)
	_, _ = w.Write([]byte{0x4D, 0x5A, 0x00, 0x00})
	w.Close()

	detail := CheckStreamContent("payload.bin", b.Bytes())
	if detail == nil {
		t.Fatalf("expected detection for decompressed PE")
	}
	if detail.RiskLevel != "CRITICAL" {
		t.Fatalf("expected CRITICAL risk for decompressed PE, got %s", detail.RiskLevel)
	}
}

func TestCheckStreamContent_ImageSpoofScript(t *testing.T) {
	// Image name but contains script markers
	data := []byte("this contains JScript somewhere")
	detail := CheckStreamContent("image.jpg", data)
	if detail == nil {
		t.Fatalf("expected detection for script in image-like stream")
	}
	if detail.RiskLevel != "CRITICAL" {
		t.Fatalf("expected CRITICAL risk, got %s", detail.RiskLevel)
	}
}

func TestCheckStreamContent_HighEntropySafeContext(t *testing.T) {
	// create high-entropy like data by cycling through many byte values
	data := make([]byte, 4096)
	for i := range data {
		data[i] = byte(i % 256)
	}

	// 'Section' is in safeKeywords; should not trigger WARNING/CRITICAL
	if det := CheckStreamContent("Section1.bin", data); det != nil {
		t.Fatalf("expected no detection for safe context, got %+v", det)
	}
}

func TestCheckStreamContent_HighEntropySuspicious(t *testing.T) {
	data := make([]byte, 4096)
	for i := range data {
		data[i] = byte(i % 256)
	}
	det := CheckStreamContent("unknown.bin", data)
	if det == nil {
		t.Fatalf("expected detection for high-entropy unknown context")
	}
	if det.RiskLevel != "WARNING" {
		t.Fatalf("expected WARNING for high-entropy unknown, got %s", det.RiskLevel)
	}
}

func TestCheckStreamContent_DLL_Entropy(t *testing.T) {
	data := make([]byte, 2048)
	for i := range data {
		data[i] = byte((i * 7) % 256)
	}
	det := CheckStreamContent("plugin.dll", data)
	if det == nil {
		t.Fatalf("expected detection for suspicious DLL entropy")
	}
	if det.RiskLevel != "WARNING" {
		t.Fatalf("expected WARNING for suspicious DLL, got %s", det.RiskLevel)
	}
}

func TestCheckStreamContent_EPS_and_SuspiciousLink(t *testing.T) {
	if det := CheckStreamContent("vector.eps", []byte("%!PS-Adobe-3.0")); det == nil {
		t.Fatalf("expected EPS detection")
	}

	if det := CheckStreamContent("doc.bin", []byte("javascript:evil()")); det == nil {
		t.Fatalf("expected suspicious link detection")
	}
}
