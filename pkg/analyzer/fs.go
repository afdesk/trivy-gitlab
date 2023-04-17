package analyzer

import (
	"bufio"
	"fmt"
	"log"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

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

func (a *fsAnalyzer) ScanCmd(options Options) ([]string, error) {
	return []string{"fs", options.Target}, nil
}

func (a *fsAnalyzer) ResolveScanners(scanners []string) []string {

	scanners = Filter(scanners, func(s string) bool {
		return s == "vuln" || s == "secret" || s == "config"
	})
	scanners = skipScanByGitlabCause(scanners, "DEPENDENCY_SCANNING_DISABLED", "vuln")
	scanners = skipScanByGitlabCause(scanners, "SECRET_DETECTION_DISABLED", "secret")
	scanners = skipScanByGitlabCause(scanners, "SAST_DISABLED", "config")

	return append(scanners, "license")

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

func (c *secretsConverter) Convert(r *types.Report) (*report.Report, error) {

	gitlabReport := report.NewReport()

	for _, res := range r.Results {
		for _, vuln := range res.Secrets {
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
					File:      res.Target,
					Commit:    GetCommitWithSecret(r.ArtifactName, res.Target, vuln.StartLine),
					LineStart: vuln.StartLine,
					LineEnd:   vuln.EndLine,
				},
			}

			gitlabReport.Vulnerabilities = append(gitlabReport.Vulnerabilities, v)
		}
	}

	return &gitlabReport, nil
}

const defaultSha = "0000000"

func GetCommitWithSecret(path, target string, line int) *report.Commit {
	blame, err := getBlame(path, target, line)
	if err != nil {
		return &report.Commit{
			Sha: defaultSha,
		}
	}
	return &report.Commit{
		Sha:     blame.Sha,
		Author:  blame.Committer,
		Message: blame.Summary,
		Date:    blame.CommitterTime,
	}
}

func getBlame(path, target string, line int) (*BlameOutput, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}

	gitDir := filepath.Join(abs, ".git")
	out, errMsg, err := piped(
		exec.Command(
			"git",
			"--git-dir", gitDir,
			"--work-tree", abs,
			"blame",
			"--line-porcelain",
			"-L", fmt.Sprintf("%d,%d", line, line),
			target,
		),
	)

	if err != nil {
		log.Println(errMsg)
		return nil, err
	}

	return parseBlameOutput(out)
}

func parseBlameOutput(out string) (*BlameOutput, error) {
	scanner := bufio.NewScanner(strings.NewReader(out))
	blame := BlameOutput{}

	scanner.Scan()
	fiestLine := scanner.Text()

	if fiestLine == "" {
		return nil, fmt.Errorf("no blame found")
	}

	splited := strings.SplitN(fiestLine, " ", 2)
	if len(splited) < 1 {
		return nil, fmt.Errorf("invalid blame output")
	}

	blame.Sha = splited[0]

	for scanner.Scan() {
		line := scanner.Text()
		splited := strings.SplitN(line, " ", 2)
		if len(splited) != 2 {
			continue
		}
		field, value := splited[0], splited[1]

		if field == "committer" {
			blame.Committer = value
		}
		if field == "summary" {
			blame.Summary = value
		}

		if field == "committer-time" {
			i, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				return nil, err
			}

			blame.CommitterTime = time.Unix(i, 0).String()
		}
	}

	return &blame, nil
}

type BlameOutput struct {
	Sha           string
	Committer     string
	Summary       string
	CommitterTime string
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
