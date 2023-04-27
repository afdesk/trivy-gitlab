package analyzer

import (
	"fmt"
	"log"
	"net/url"
	"regexp"
	"strings"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"
	"gitlab.com/gitlab-org/security-products/analyzers/report/v3"
)

const (
	identifierTypeSecret    = "secret"
	identifierTypeMisconfig = "misconfig"

	defaultSha = "0000000"
)

var httpOrHttpsProtocol = regexp.MustCompile(`^https?://.+`)

type containerConverter struct{}

func NewContainerConverter() *containerConverter {
	return &containerConverter{}
}

func (c *containerConverter) Meta() converterMeta {
	return converterMeta{
		ID:            "container-scanning",
		ScanType:      report.CategoryContainerScanning,
		ReportVersion: report.Version{Major: 15, Minor: 0, Patch: 0, PreRelease: ""},
	}
}

func (c *containerConverter) Convert(r *types.Report) (*report.Report, error) {
	return &report.Report{
		Vulnerabilities: makeVulnerabilities(r),
	}, nil
}

type dependencyConverter struct{}

func NewDependencyConverter() *dependencyConverter {
	return &dependencyConverter{}
}

func (c *dependencyConverter) Meta() converterMeta {
	return converterMeta{
		ID:            "dependency-scanning",
		ScanType:      report.CategoryDependencyScanning,
		ReportVersion: report.Version{Major: 15, Minor: 0, Patch: 0, PreRelease: ""},
	}
}

func (c *dependencyConverter) Convert(r *types.Report) (*report.Report, error) {
	vulnerabilities := []report.Vulnerability{}
	atype := r.ArtifactType
	if atype == ftypes.ArtifactFilesystem {
		makeVulnerabilities(r)
	}
	return &report.Report{
		Vulnerabilities: vulnerabilities,
		DependencyFiles: makeDependencyFiles(r, func(res types.Result) bool {
			onlyContainerDependency := atype == ftypes.ArtifactContainerImage && res.Class == types.ClassOSPkg
			onlyLangDependency := atype == ftypes.ArtifactFilesystem && res.Class == types.ClassLangPkg
			return onlyContainerDependency || onlyLangDependency
		}),
	}, nil
}

type secretsConverter struct{}

func NewSecretsConverter() *secretsConverter {
	return &secretsConverter{}
}

func (c *secretsConverter) Meta() converterMeta {
	return converterMeta{
		ID:            "secret-detection",
		ScanType:      report.CategorySecretDetection,
		ReportVersion: report.Version{Major: 15, Minor: 0, Patch: 0, PreRelease: ""},
	}
}

func (c *secretsConverter) Convert(r *types.Report) (*report.Report, error) {

	gitlabReport := report.NewReport()

	for _, res := range r.Results {
		for _, vuln := range res.Secrets {
			v := report.Vulnerability{
				Severity:    convertSeverity(vuln.Severity),
				Name:        vuln.Title,
				Description: vuln.RuleID,
				Identifiers: []report.Identifier{
					{
						Type:  identifierTypeSecret,
						Value: vuln.Title,
						Name:  vuln.Title,
					},
				},
				Location: report.Location{
					File:      res.Target,
					Commit:    &report.Commit{Sha: defaultSha},
					LineStart: vuln.StartLine,
					LineEnd:   vuln.EndLine,
				},
			}

			gitlabReport.Vulnerabilities = append(gitlabReport.Vulnerabilities, v)
		}
	}

	return &gitlabReport, nil
}

type misconfigConverter struct{}

func NewMisconfigConverter() *misconfigConverter {
	return &misconfigConverter{}
}

func (c *misconfigConverter) Meta() converterMeta {
	return converterMeta{
		ID:            "misconfig-detection",
		ScanType:      report.CategorySast,
		ReportVersion: report.Version{Major: 15, Minor: 0, Patch: 0, PreRelease: ""},
	}
}

func (c *misconfigConverter) Convert(r *types.Report) (*report.Report, error) {
	gitlabReport := report.NewReport()

	for _, r := range r.Results {
		for _, vuln := range r.Misconfigurations {
			v := report.Vulnerability{
				Name:        vuln.Title,
				Description: vuln.Description,
				Severity:    convertSeverity(vuln.Severity),
				Solution:    vuln.Resolution,
				Identifiers: []report.Identifier{
					{
						Type:  identifierTypeMisconfig,
						Value: vuln.Title,
						Name:  vuln.Title,
					},
				},
				Location: report.Location{
					File:      r.Target,
					LineStart: vuln.CauseMetadata.StartLine,
					LineEnd:   vuln.CauseMetadata.EndLine,
				},
			}

			gitlabReport.Vulnerabilities = append(gitlabReport.Vulnerabilities, v)
		}
	}

	return &gitlabReport, nil
}

func convertSeverity(severity string) report.SeverityLevel {
	return report.ParseSeverityLevel(severity)
}

func makeLinks(references []string) []report.Link {
	convertToLink := func(ref string) report.Link { return report.Link{URL: ref} }
	return mapf(filterf(mapf(references, fixUrlWithSpace), isValidUrl), convertToLink)
}

func makeDependencyFiles(r *types.Report, filter func(r types.Result) bool) []report.DependencyFile {
	return mapf(filterf(r.Results, filter), func(r types.Result) report.DependencyFile {
		return report.DependencyFile{
			Path:           r.Target,
			PackageManager: report.PackageManager(r.Type),
			Dependencies: mapf(r.Packages, func(pkg ftypes.Package) report.Dependency {
				return report.Dependency{
					Package: report.Package{
						Name: valueOrDefault(pkg.SrcName, pkg.Name),
					},
					Version: valueOrDefault(pkg.SrcVersion, pkg.Version),
				}
			}),
		}
	})
}

func makeVulnerabilities(r *types.Report) []report.Vulnerability {

	var vulnerabilities []report.Vulnerability

	for _, res := range r.Results {

		for _, v := range res.Vulnerabilities {
			vuln := report.Vulnerability{
				Name:        v.Title,
				Description: v.Description,
				Severity:    convertSeverity(v.Severity),
				Solution:    makeSolution(v),
				Identifiers: []report.Identifier{
					{
						Type:  report.IdentifierTypeCVE,
						Name:  v.VulnerabilityID,
						Value: v.VulnerabilityID,
						URL:   v.PrimaryURL,
					},
				},
				Location: report.Location{
					Dependency: &report.Dependency{
						Package: report.Package{
							Name: v.PkgName,
						},
						Version: v.InstalledVersion,
					},
					File:            res.Target,
					OperatingSystem: makeOperatingSystem(r),
					Image:           makeImage(r),
				},
				Links: makeLinks(v.References),
			}
			vulnerabilities = append(vulnerabilities, vuln)

		}
	}

	return vulnerabilities
}

func makeOperatingSystem(r *types.Report) string {
	if r.Metadata.OS == nil {
		return ""
	}
	return fmt.Sprintf("%s %s", r.Metadata.OS.Family, r.Metadata.OS.Name)
}

func makeImage(r *types.Report) string {
	if !strings.Contains(r.ArtifactName, ":") {
		return fmt.Sprintf("%s:latest", r.ArtifactName)
	}
	return r.ArtifactName
}

func makeSolution(vuln types.DetectedVulnerability) string {
	if vuln.FixedVersion != "" {
		return fmt.Sprintf("Upgrade %s to version %s", vuln.PkgName, vuln.FixedVersion)
	}
	return ""
}

func fixUrlWithSpace(u string) string {
	if spaceIndex := strings.Index(u, " "); spaceIndex != -1 {
		return u[:spaceIndex]
	}
	return u
}

func isHttpOrHttps(u string) bool {
	return httpOrHttpsProtocol.MatchString(u)
}

func isValidUrl(u string) bool {
	url, err := url.ParseRequestURI(u)
	if err != nil {
		log.Println(err)
		return false
	}
	return isHttpOrHttps(url.String())
}
