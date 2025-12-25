//go:build !cli
// +build !cli

package main

import (
	"net/url"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"project_apollo/internal/report"
	"project_apollo/internal/ui"
)

func main() {
	myApp := app.New()
	// internal/ui 패키지에 정의된 고대비 테마 적용
	myApp.Settings().SetTheme(&ui.HighContrastTheme{})

	myWindow := myApp.NewWindow("HWP 기초 보안 스캐너")
	myWindow.Resize(fyne.NewSize(750, 600))

	// 1. 상단 타이틀 영역
	titleLabel := widget.NewLabel("HWP/HWPX 악성코드 기초 분석기")
	titleLabel.TextStyle = fyne.TextStyle{Bold: true}
	titleLabel.Alignment = fyne.TextAlignCenter

	// 버전 및 프로젝트 링크 정보
	versionLabel := widget.NewLabel("버전 1.0 | 제작자: Jin-Doh |")
	versionLabel.Alignment = fyne.TextAlignCenter

	projectLabel := widget.NewLabel("프로젝트 URL: ")
	projectURL := "https://github.com/Jin-Doh/Project-Apollo"
	parsedURL, _ := url.Parse(projectURL)
	projectLink := widget.NewHyperlink("Github", parsedURL)

	versionContainer := container.NewCenter(container.NewHBox(versionLabel, projectLabel, projectLink))

	descLabel := widget.NewLabel("파일을 아래로 드래그하면 보안 분석 리포트가 생성됩니다.")
	descLabel.Alignment = fyne.TextAlignCenter

	topContainer := container.NewVBox(titleLabel, versionContainer, descLabel)

	// 2. 결과 출력 영역
	resultEntry := widget.NewMultiLineEntry()
	resultEntry.SetText("대기 중...\n\n(여기에 상세 분석 리포트가 표시됩니다.)")
	resultEntry.Disable() // 수정 방지 (테마 덕분에 검은 글씨 유지)
	resultEntry.TextStyle = fyne.TextStyle{Monospace: true}

	contentArea := container.NewPadded(resultEntry)

	// 3. 하단 복사 버튼
	copyButton := widget.NewButtonWithIcon("리포트 전체 복사", theme.ContentCopyIcon(), func() {
		myWindow.Clipboard().SetContent(resultEntry.Text)
		fyne.CurrentApp().SendNotification(&fyne.Notification{
			Title:   "복사 완료",
			Content: "분석 리포트가 클립보드에 복사되었습니다.",
		})
	})
	copyButton.Importance = widget.HighImportance

	// 4. 드래그 앤 드롭 이벤트 핸들러
	myWindow.SetOnDropped(func(pos fyne.Position, uris []fyne.URI) {
		resultEntry.SetText("🔍 정밀 분석 중입니다... 잠시만 기다려주세요.")

		var fullReport strings.Builder
		for _, u := range uris {
			filePath := u.Path()
			// internal/report 패키지의 분석 로직 호출
			reportText := report.AnalyzeFile(filePath)
			fullReport.WriteString(reportText + "\n\n")
		}
		resultEntry.SetText(fullReport.String())
	})

	// 5. 레이아웃 배치 및 실행
	mainContent := container.NewBorder(
		container.NewPadded(topContainer), // Top
		container.NewPadded(copyButton),   // Bottom
		nil, nil,                          // Left, Right
		contentArea, // Center
	)

	myWindow.SetContent(mainContent)
	myWindow.ShowAndRun()
}
