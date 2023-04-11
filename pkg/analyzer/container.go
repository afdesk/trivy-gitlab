package analyzer

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/Jeffail/gabs/v2"
)

type containerAnalyzer struct {
	imageName        string
	reportFileName   string
	templateFileName string
}

type ContainerOptions struct {
	GlobalOptions
}

func (o ContainerOptions) Global() GlobalOptions {
	return o.GlobalOptions
}

func NewContainerAnalyzer(imgName string) (*containerAnalyzer, error) {
	return &containerAnalyzer{
		imgName,
		"trivy-container-scanning-report.json",
		"container-scanning.tpl",
	}, nil
}

func (a *containerAnalyzer) TemplateFileName() string {
	return a.templateFileName
}

func (a *containerAnalyzer) ReportFileName() string {
	return a.reportFileName
}

func (a *containerAnalyzer) ScanCommand(outputFileName, templateFile string, options ContainerOptions) []string {
	var cmd = []string{"image"}
	if options.Debug {
		cmd = append(cmd, "--offline-scan", "--skip-update")
	}
	return append(
		cmd,
		"--no-progress",
		"--scanners", "vuln",
		"-f", "template",
		"-o", outputFileName,
		"-t", fmt.Sprintf("@%s", templateFile),
		a.imageName,
	)
}

func (a *containerAnalyzer) Convert(trivy_report *gabs.Container) error {

	for _, vuln := range trivy_report.S("vulnerabilities").Children() {

		for _, link := range vuln.S("links").Children() {
			vuln_url, ok := link.Path("url").Data().(string)
			if !ok {
				continue
			}

			splited_url := strings.Split(vuln_url, " ")
			if len(splited_url) < 2 {
				continue
			}

			if _, err := url.ParseRequestURI(splited_url[0]); err == nil {
				link.SetP(splited_url[0], "url")
			}
		}
	}

	// TODO calc ID
	// id_fields := []string{"message", "description", "cve", "severity", "solution", "scanner", "location", "identifiers"}
	// var id_values []interface{}
	// sum := sha256.Sum256([]byte(id_values))

	return nil
}
