package ui

import (
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/theme"
)

// HighContrastTheme improves readability for the GUI.
type HighContrastTheme struct{}

var _ fyne.Theme = (*HighContrastTheme)(nil)

func (m HighContrastTheme) Color(n fyne.ThemeColorName, v fyne.ThemeVariant) color.Color {
	// 텍스트는 무조건 검은색 (Disable 상태 포함)
	if n == theme.ColorNameForeground || n == theme.ColorNameDisabled {
		return color.Black
	}
	// 입력창 배경은 흰색
	if n == theme.ColorNameInputBackground {
		return color.White
	}
	return theme.LightTheme().Color(n, v)
}

func (m HighContrastTheme) Font(s fyne.TextStyle) fyne.Resource {
	return theme.LightTheme().Font(s)
}

func (m HighContrastTheme) Icon(n fyne.ThemeIconName) fyne.Resource {
	return theme.LightTheme().Icon(n)
}

func (m HighContrastTheme) Size(n fyne.ThemeSizeName) float32 {
	return theme.LightTheme().Size(n)
}
