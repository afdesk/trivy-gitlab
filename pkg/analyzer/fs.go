package analyzer

import (
	"fmt"

	"github.com/aquasecurity/trivy/pkg/types"
	"gitlab.com/gitlab-org/security-products/analyzers/report/v3"
)

const (
	identifierTypeSecret    = "secret"
	identifierTypeMisconfig = "misconfig"
)

type fsAnalyzer struct{}

func NewFsAnalyzer() *fsAnalyzer {
	return &fsAnalyzer{}
}

func (a *fsAnalyzer) ScanCmd(options Options) (string, error) {
	return fmt.Sprintf("fs %s", options.Target), nil
}

func (a *fsAnalyzer) Converters() []Converter {
	return []Converter{
		NewDependencyConverter(),
		NewSecretsConverter(),
		NewMisconfigConverter(),
	}
}

type dependencyConverter struct{}

func NewDependencyConverter() *dependencyConverter {
	return &dependencyConverter{}
}

func (c *dependencyConverter) Meta() ConverterMeta {
	return ConverterMeta{
		ID:            "dependency-scanning",
		ScanType:      report.CategoryDependencyScanning,
		TrivyScanner:  "vuln",
		ReportVersion: report.Version{Major: 15, Minor: 0, Patch: 0, PreRelease: ""},
	}

}

func (c *dependencyConverter) Skip(o *Options, env Env) bool {
	return false
}

func (c *dependencyConverter) Convert(r *types.Report) (*report.Report, error) {
	gitlabReport := report.NewReport()

	for _, r := range r.Results {
		for _, vuln := range r.Vulnerabilities {
			v := report.Vulnerability{
				Severity:    ConvertSeverity(vuln.Severity),
				Name:        vuln.Title,
				Description: vuln.Description,
				Identifiers: []report.Identifier{
					{
						Type:  report.IdentifierTypeCVE,
						Value: vuln.VulnerabilityID,
						Name:  vuln.VulnerabilityID,
						URL:   vuln.PrimaryURL,
					},
				},
				Location: report.Location{
					File: r.Target,
					Dependency: &report.Dependency{
						Package: report.Package{
							Name: vuln.PkgName,
						},
						Version: vuln.InstalledVersion,
					},
				},
				Links: MakeLinks(vuln.References),
			}

			gitlabReport.Vulnerabilities = append(gitlabReport.Vulnerabilities, v)
		}
	}

	gitlabReport.DependencyFiles = MakeDependencyFiles(r, func(r types.Result) bool {
		return len(r.Vulnerabilities) > 0 && r.Type == types.ClassLangPkg
	})

	return &gitlabReport, nil
}

type secretsConverter struct{}

func NewSecretsConverter() *secretsConverter {
	return &secretsConverter{}
}

func (c *secretsConverter) Meta() ConverterMeta {
	return ConverterMeta{
		ID:            "secret-detection",
		ScanType:      report.CategorySecretDetection,
		TrivyScanner:  "secret",
		ReportVersion: report.Version{Major: 15, Minor: 0, Patch: 0, PreRelease: ""},
	}
}

func (c *secretsConverter) Skip(o *Options, env Env) bool {
	return false
}

func (c *secretsConverter) Convert(r *types.Report) (*report.Report, error) {

	gitlabReport := report.NewReport()

	for _, r := range r.Results {
		for _, vuln := range r.Secrets {
			v := report.Vulnerability{
				Severity:    ConvertSeverity(vuln.Severity),
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
					File: r.Target,
					// TODO use git diff to get the commit

					Commit: &report.Commit{
						Sha: "TODO",
					},
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

func (c *misconfigConverter) Meta() ConverterMeta {
	return ConverterMeta{
		ID:            "misconfig-detection",
		ScanType:      report.CategorySast,
		TrivyScanner:  "config",
		ReportVersion: report.Version{Major: 15, Minor: 0, Patch: 0, PreRelease: ""},
	}
}

func (c *misconfigConverter) Skip(o *Options, env Env) bool {
	return false
}

func (c *misconfigConverter) Convert(r *types.Report) (*report.Report, error) {
	gitlabReport := report.NewReport()

	for _, r := range r.Results {
		for _, vuln := range r.Misconfigurations {
			v := report.Vulnerability{
				Name:        vuln.Title,
				Description: vuln.Description,
				Severity:    ConvertSeverity(vuln.Severity),
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
