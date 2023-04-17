package analyzer

import (
	"fmt"
	"os"
	"strings"

	"github.com/aquasecurity/trivy/pkg/types"
	"gitlab.com/gitlab-org/security-products/analyzers/report/v3"
)

type imageAnalyzer struct{}

func NewImageAnalyzer() *imageAnalyzer {
	return &imageAnalyzer{}
}

func (a *imageAnalyzer) ScanCmd(options Options) ([]string, error) {
	target := options.Target
	if target == "" {
		imageName, err := extractImageName()
		if err != nil {
			return nil, fmt.Errorf("failed to extract image name: %w", err)
		}
		target = imageName
	}

	return []string{"image", target}, nil
}

func (a *imageAnalyzer) ResolveScanners(scanners []string) []string {
	scanners = Filter(scanners, func(s string) bool {
		return s == "vuln"
	})
	return skipScanByGitlabCause(scanners, "CONTAINER_SCANNING_DISABLED", "vuln")
}

func (a *imageAnalyzer) Converters() []Converter {
	return []Converter{
		NewContainerConverter(),
		NewContainerDependencyConverter(),
	}
}

type containerConverter struct{}

func NewContainerConverter() *containerConverter {
	return &containerConverter{}
}

func (c *containerConverter) Meta() ConverterMeta {
	return ConverterMeta{
		ID:            "container-scanning",
		ScanType:      report.CategoryContainerScanning,
		TrivyScanner:  "vuln",
		ReportVersion: report.Version{Major: 15, Minor: 0, Patch: 0, PreRelease: ""},
	}
}

func (c *containerConverter) Convert(r *types.Report) (*report.Report, error) {
	gitlabReport := report.NewReport()

	for _, res := range r.Results {

		for _, v := range res.Vulnerabilities {
			vuln := report.Vulnerability{
				Name:     v.VulnerabilityID,
				Severity: ConvertSeverity(v.Severity),
				Solution: MakeSolution(v),
				Location: report.Location{
					Dependency: &report.Dependency{
						Package: report.Package{
							Name: v.PkgName,
						},
						Version: v.InstalledVersion,
					},
					OperatingSystem: makeOperatingSystem(r),
					Image:           makeImage(r),
				},
				Identifiers: []report.Identifier{
					{
						Type:  report.IdentifierTypeCVE,
						Name:  v.VulnerabilityID,
						Value: v.VulnerabilityID,
						URL:   v.PrimaryURL,
					},
				},
				Links: MakeLinks(v.References),
			}

			gitlabReport.Vulnerabilities = append(gitlabReport.Vulnerabilities, vuln)

		}
	}

	return &gitlabReport, nil
}

func makeOperatingSystem(r *types.Report) string {
	return fmt.Sprintf("%s %s", r.Metadata.OS.Family, r.Metadata.OS.Name)
}

func makeImage(r *types.Report) string {
	if !strings.Contains(r.ArtifactName, ":") {
		return fmt.Sprintf("%s:latest", r.ArtifactName)
	}
	return r.ArtifactName
}

type containerDepConverter struct{}

func NewContainerDependencyConverter() *containerDepConverter {
	return &containerDepConverter{}
}

func (c *containerDepConverter) Meta() ConverterMeta {
	return ConverterMeta{
		ID:            "dependency-scanning",
		ScanType:      report.CategoryDependencyScanning,
		TrivyScanner:  "vuln",
		ReportVersion: report.Version{Major: 15, Minor: 0, Patch: 0, PreRelease: ""},
	}
}

func (c *containerDepConverter) Convert(r *types.Report) (*report.Report, error) {
	return &report.Report{
		Vulnerabilities: []report.Vulnerability{},
		DependencyFiles: MakeDependencyFiles(r, func(r types.Result) bool {
			return r.Class == types.ClassOSPkg
		}),
	}, nil
}

func extractImageName() (string, error) {

	if value, ok := os.LookupEnv("TS_IMAGE"); ok {
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

	return getEnvOrError("CI_COMMIT_SHA")

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
