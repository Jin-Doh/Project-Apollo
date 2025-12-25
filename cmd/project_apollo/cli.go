//go:build cli
// +build cli

package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"project_apollo/internal/report"
)

func main() {
	help := flag.Bool("h", false, "Show help")
	version := flag.Bool("v", false, "Show version")
	flag.Parse()

	if *help {
		fmt.Fprintf(os.Stdout, "Project Apollo CLI\n")
		fmt.Fprintf(os.Stdout, "Usage: %s [file_or_directory ...]\n", filepath.Base(os.Args[0]))
		fmt.Fprintf(os.Stdout, "Analyze HWP/HWPX files and print human-readable reports.\n")
		return
	}
	if *version {
		fmt.Println("Project Apollo (CLI) version 1.0")
		return
	}

	args := flag.Args()
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Error: provide at least one file or directory to analyze. Use -h for help.")
		os.Exit(2)
	}

	for _, p := range args {
		fi, err := os.Stat(p)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Skipping %s: %v\n", p, err)
			continue
		}

		if fi.IsDir() {
			// walk directory and analyze files
			filepath.Walk(p, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					fmt.Fprintf(os.Stderr, "walk error %s: %v\n", path, err)
					return nil
				}
				if info.IsDir() {
					return nil
				}
				// only attempt common extensions
				ext := filepath.Ext(strings.ToLower(path))
				if ext == ".hwp" || ext == ".hwpx" || ext == ".hwpx" || ext == ".doc" || ext == ".docx" {
					out := report.AnalyzeFile(path)
					fmt.Println(out)
				}
				return nil
			})
			continue
		}

		out := report.AnalyzeFile(p)
		fmt.Println(out)
	}
}
