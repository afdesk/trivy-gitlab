package analyzer

import (
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/Jeffail/gabs/v2"
)

type containerAnalyzer struct {
	imageName        string
	reportFileName   string
	templateFileName string
}

func NewContainerAnalyzer() (*containerAnalyzer, error) {
	imageName, err := extractImageName()
	if err != nil {
		return nil, err
	}
	return &containerAnalyzer{
		imageName,
		"container-scanning.json",
		"container-scanning.tpl",
	}, nil
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

func extractImageName() (string, error) {
	if value, ok := os.LookupEnv("CS_IMAGE"); ok {
		return value, nil
	}
	if value, ok := os.LookupEnv("DOCKER_IMAGE"); ok {
		return value, nil
	}

	applicationRepository, err := getApplicationRepository()
	if err != nil {
		return "", err
	}

	applicationTag, err := getApplicationTag()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s:%s", applicationRepository, applicationTag), nil
}

func getApplicationRepository() (string, error) {
	if value, ok := os.LookupEnv("CI_APPLICATION_REPOSITORY"); ok {
		return value, nil
	}

	return getDefaultApplicationRepository()
}

func getApplicationTag() (string, error) {
	if value, ok := os.LookupEnv("CI_APPLICATION_TAG"); ok {
		return value, nil
	}

	return getEnvOrError("CI_APPLICATION_TAG")
}

func getDefaultApplicationRepository() (string, error) {

	registryImage, err := getEnvOrError("CI_REGISTRY_IMAGE")
	if err != nil {
		return "", err
	}

	commitRefSlug, err := getEnvOrError("CI_COMMIT_REF_SLUG")
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%s/%s", registryImage, commitRefSlug), nil
}

func getEnvOrError(key string) (string, error) {

	if value, ok := os.LookupEnv(key); ok {
		return value, nil
	}

	return "", fmt.Errorf("none of the environment variables %s were found but are required for execution", key)
}
