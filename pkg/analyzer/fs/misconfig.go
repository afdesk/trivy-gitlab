package fs

import (
	"fmt"

	"github.com/Jeffail/gabs/v2"
	"github.com/afdesk/trivy-gitlab/pkg/analyzer"
)

type MisconfigOptions struct {
	analyzer.GlobalOptions
}

func (o MisconfigOptions) Global() analyzer.GlobalOptions {
	return o.GlobalOptions
}

type misconfigAnalyzer struct {
	path string
}

func NewMisconfigAnalyzer(path string) *misconfigAnalyzer {
	return &misconfigAnalyzer{path}
}

func (a *misconfigAnalyzer) Meta() analyzer.AnalyzerMeta {
	return analyzer.AnalyzerMeta{
		Id:            "misconfig-detection",
		Type:          "sast",
		SchemaVersion: "15.0.0",
	}
}

func (a *misconfigAnalyzer) Skip() bool {
	return false
}

func (a *misconfigAnalyzer) ScanCommand(outputFileName, templateFile string, options MisconfigOptions) []string {
	return []string{
		"fs",
		a.path,
		"--no-progress",
		"--scanners", "config",
		"-f", "template",
		"-o", outputFileName,
		"-t", fmt.Sprintf("@%s", templateFile),
	}
}

func (a *misconfigAnalyzer) Convert(trivyReport *gabs.Container) error {

	for _, vuln := range trivyReport.S("vulnerabilities").Children() {
		analyzer.FixId(vuln)
		analyzer.FixLineNumbers(vuln)
	}

	return nil
}
