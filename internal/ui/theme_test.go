package ui

import (
	"image/color"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/theme"
)

func TestHighContrastTheme_Colors(t *testing.T) {
	var th HighContrastTheme
	// ThemeVariant is an alias; pass zero value
	var v fyne.ThemeVariant

	c := th.Color(theme.ColorNameForeground, v)
	r1, g1, b1, a1 := c.RGBA()
	r2, g2, b2, a2 := color.Black.RGBA()
	if r1 != r2 || g1 != g2 || b1 != b2 || a1 != a2 {
		t.Fatalf("expected foreground color to be black, got %v", c)
	}

	c2 := th.Color(theme.ColorNameInputBackground, v)
	r3, g3, b3, _ := c2.RGBA()
	// white background expected
	rr, gg, bb, _ := color.White.RGBA()
	if r3 != rr || g3 != gg || b3 != bb {
		t.Fatalf("expected input background to be white, got %v", c2)
	}
}
