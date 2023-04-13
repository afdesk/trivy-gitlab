package fs

import (
	"fmt"

	"github.com/Jeffail/gabs/v2"
	"github.com/afdesk/trivy-gitlab/pkg/analyzer"
)

type secretAnalyzer struct {
	path string
}

type SecretOptions struct {
	analyzer.GlobalOptions
}

func (o SecretOptions) Global() analyzer.GlobalOptions {
	return o.GlobalOptions
}

func NewSecretAnalyzer(path string) *secretAnalyzer {
	return &secretAnalyzer{path}
}

func (a *secretAnalyzer) Meta() analyzer.AnalyzerMeta {
	return analyzer.AnalyzerMeta{
		Id:            "secret-detection",
		Type:          "secret_detection",
		SchemaVersion: "15.0.0",
	}
}

func (a *secretAnalyzer) Skip() bool {
	return false
}

func (a *secretAnalyzer) ScanCommand(outputFileName, templateFile string, options SecretOptions) []string {
	return []string{
		"fs",
		a.path,
		"--no-progress",
		"--scanners", "secret",
		"-f", "template",
		"-o", outputFileName,
		"-t", fmt.Sprintf("@%s", templateFile),
	}
}

func (a *secretAnalyzer) Convert(trivyReport *gabs.Container) error {
	for _, vuln := range trivyReport.S("vulnerabilities").Children() {
		analyzer.FixId(vuln)
		analyzer.FixLineNumbers(vuln)
	}
	return nil
}
