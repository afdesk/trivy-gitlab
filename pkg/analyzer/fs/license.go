package fs

import (
	"fmt"

	"github.com/Jeffail/gabs/v2"
	"github.com/afdesk/trivy-gitlab/pkg/analyzer"
)

// TODO

type licenseAnalyzer struct {
}

type LicenseOptions struct {
	analyzer.GlobalOptions
}

func (o LicenseOptions) Global() analyzer.GlobalOptions {
	return o.GlobalOptions
}

func NewLicenseAnalyzer() *licenseAnalyzer {
	return &licenseAnalyzer{}
}

func (a *licenseAnalyzer) Meta() analyzer.AnalyzerMeta {
	return analyzer.AnalyzerMeta{
		Id:            "license-scanning",
		Type:          "sast",
		SchemaVersion: "15.0.0",
	}
}

func (a *licenseAnalyzer) Skip() bool {
	return false
}

func (a *licenseAnalyzer) ScanCommand(outputFileName, templateFile string, options DependencyOptions) []string {
	return []string{
		"fs",
		"--no-progress",
		"--scanners", "license",
		"-f", "template",
		"-o", outputFileName,
		"-t", fmt.Sprintf("@%s", templateFile),
	}
}

func (a *licenseAnalyzer) Convert(trivyReport *gabs.Container) error {

	return nil
}
