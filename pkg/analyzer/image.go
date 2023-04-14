package analyzer

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/trivy/pkg/types"
	"gitlab.com/gitlab-org/security-products/analyzers/report/v3"
)

type imageAnalyzer struct {
}

func NewImageAnalyzer() *imageAnalyzer {
	return &imageAnalyzer{}
}

func (a *imageAnalyzer) ScanCmd(options Options) (string, error) {
	return fmt.Sprintf("image %s", options.Target), nil
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

func (c *containerConverter) Skip(o *Options, env Env) bool {
	return false
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

func (c *containerDepConverter) Skip(o *Options, env Env) bool {
	return false
}

func (c *containerDepConverter) Convert(r *types.Report) (*report.Report, error) {
	return &report.Report{
		Vulnerabilities: []report.Vulnerability{},
		DependencyFiles: MakeDependencyFiles(r, func(r types.Result) bool {
			return r.Class == types.ClassOSPkg
		}),
	}, nil
}
