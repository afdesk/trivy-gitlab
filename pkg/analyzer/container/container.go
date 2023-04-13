package container

import (
	"fmt"

	"github.com/Jeffail/gabs/v2"
	"github.com/afdesk/trivy-gitlab/pkg/analyzer"
)

type ContainerOptions struct {
	analyzer.GlobalOptions
}

func (o ContainerOptions) Global() analyzer.GlobalOptions {
	return o.GlobalOptions
}

type containerAnalyzer struct {
	imageName string
}

func NewContainerAnalyzer(imgName string) (*containerAnalyzer, error) {
	return &containerAnalyzer{imgName}, nil
}

// TODO: migrate to 15 version
func (a *containerAnalyzer) Meta() analyzer.AnalyzerMeta {
	return analyzer.AnalyzerMeta{
		Id:            "container-scanning",
		Type:          "container_scanning",
		SchemaVersion: "15.0.0",
	}
}

func (a *containerAnalyzer) Skip() bool {
	return false
}

func (a *containerAnalyzer) ScanCommand(outputFileName, templateFile string, options ContainerOptions) []string {
	return []string{
		"image", "--no-progress",
		"--scanners", "vuln",
		"-f", "template",
		"-o", outputFileName,
		"-t", fmt.Sprintf("@%s", templateFile),
		a.imageName,
	}
}

func (a *containerAnalyzer) Convert(trivyReport *gabs.Container) error {

	for _, vuln := range trivyReport.S("vulnerabilities").Children() {
		analyzer.FixId(vuln)
		analyzer.FixLinks(vuln)
		analyzer.FixImageAndOs(vuln)
	}
	return nil
}
