package analyzer

import (
	"fmt"
	"os"
	"strings"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"
	"gitlab.com/gitlab-org/security-products/analyzers/report/v3"
)

func ConvertSeverity(severity string) report.SeverityLevel {
	return report.ParseSeverityLevel(strings.ToLower(severity))
}

func MakeLinks(references []string) []report.Link {
	convertToLink := func(ref string) report.Link { return report.Link{URL: ref} }
	return Map(Filter(Map(references, fixUrlWithSpace), isValidUrl), convertToLink)
}

func MakeDependencyFiles(r *types.Report, filter func(r types.Result) bool) []report.DependencyFile {
	return Map(Filter(r.Results, filter), func(r types.Result) report.DependencyFile {
		return report.DependencyFile{
			Path:           r.Target,
			PackageManager: report.PackageManager(r.Type),
			Dependencies: Map(r.Packages, func(pkg ftypes.Package) report.Dependency {
				return report.Dependency{
					Package: report.Package{
						Name: ValueOrDefault(pkg.SrcName, pkg.Name),
					},
					Version: ValueOrDefault(pkg.SrcVersion, pkg.Version),
				}
			}),
		}
	})
}

func MakeSolution(vuln types.DetectedVulnerability) string {
	if vuln.FixedVersion != "" {
		return fmt.Sprintf("Upgrade %s to version %s", vuln.PkgName, vuln.FixedVersion)
	}
	return ""
}

func isScanningDisabled(key string) bool {
	if scanningDisabled, ok := os.LookupEnv(key); ok && scanningDisabled == "true" {
		return true
	}
	return false
}
