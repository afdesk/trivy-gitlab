package fs

import (
	"fmt"

	"github.com/Jeffail/gabs/v2"
	"github.com/afdesk/trivy-gitlab/pkg/analyzer"
)

type DependencyOptions struct {
	analyzer.GlobalOptions
}

func (o DependencyOptions) Global() analyzer.GlobalOptions {
	return o.GlobalOptions
}

type dependencyAnalyzer struct {
	path string
}

func NewDependencyAnalyzer(path string) *dependencyAnalyzer {
	return &dependencyAnalyzer{path}
}

func (a *dependencyAnalyzer) Meta() analyzer.AnalyzerMeta {
	return analyzer.AnalyzerMeta{
		Id:            "dependency-scanning",
		Type:          "dependency_scanning",
		SchemaVersion: "15.0.0",
	}
}

func (a *dependencyAnalyzer) Skip() bool {
	return false
}

func (a *dependencyAnalyzer) ScanCommand(outputFileName, templateFile string, options DependencyOptions) []string {
	return []string{
		"fs",
		a.path,
		"--list-all-pkgs",
		"--no-progress",
		"--scanners", "vuln",
		"-f", "template",
		"-o", outputFileName,
		"-t", fmt.Sprintf("@%s", templateFile),
	}
}

func (a *dependencyAnalyzer) Convert(trivyReport *gabs.Container) error {
	for _, vuln := range trivyReport.S("vulnerabilities").Children() {
		analyzer.FixId(vuln)
	}
	return nil
}
