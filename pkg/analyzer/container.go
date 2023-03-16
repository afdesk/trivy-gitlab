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

func NewContainerAnalyzer(imageName string) *containerAnalyzer {
	return &containerAnalyzer{
		imageName,
		"container-scanning.json",
		"container-scanning.tpl",
	}
}

func (a *containerAnalyzer) TemplateFileName() string {
	return a.templateFileName
}

func (a *containerAnalyzer) ReportFileName() string {
	return a.reportFileName
}

func (a *containerAnalyzer) ScanCommand(outputFileName, templateFile string) []string {
	return []string{"image",
		"--no-progress",
		"--offline-scan",
		"--skip-update",
		"--scanners", "vuln",
		"-f", "template",
		"-o", outputFileName,
		"-t", fmt.Sprintf("@%s", templateFile),
		a.imageName}
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
