package analyzer

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Jeffail/gabs/v2"
)

const gitlabReportTimePattern = "2006-01-02T15:04:05"
const unknownVersion = "unknown"

type Analyzer[O any] interface {
	Meta() AnalyzerMeta
	ScanCommand(outputFileName, templateFile string, options O) []string
	Convert(trivyReport *gabs.Container) error
}

type AnalyzerMeta struct {
	Id            string
	Type          string
	SchemaVersion string
}

func Run[O WithGlobalOptions](
	ctx context.Context,
	getAnalyzer func() (Analyzer[O], error), options O,
) error {

	analyzer, err := getAnalyzer()
	if err != nil {
		return err
	}

	dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		return err
	}

	templateFile := valueOrDefault(
		options.Global().TemplatePath,
		filepath.Join(dir, "templates", "report", fmt.Sprintf("%s.tpl", analyzer.Meta().Id)),
	)

	trivyOutputFile := filepath.Join(dir, "temp.json")
	scanCommand := analyzer.ScanCommand(trivyOutputFile, templateFile, options)

	if options.Global().Debug {
		scanCommand = append(scanCommand, "--offline-scan", "--skip-db-update")
	}

	scan := func() error {
		return execute(ctx, "trivy", scanCommand)
	}
	startScanTime, endScanTime, err := formattedMeasure(scan)
	if err != nil {
		return err
	}

	trivyReport, err := gabs.ParseJSONFile(trivyOutputFile)
	if err != nil {
		return err
	}

	// common properties
	trivyReport.Set(analyzer.Meta().SchemaVersion, "version")
	trivyReport.SetP(analyzer.Meta().Type, "scan.type")
	trivyReport.SetP("trivy-gitlab", "scan.analyzer.id")
	trivyReport.SetP("trivy-gitlab plguin", "scan.analyzer.name")
	trivyReport.SetP("afdesk", "scan.analyzer.vendor.name")
	trivyReport.SetP(pluginVersion(), "scan.analyzer.version")

	trivyReport.SetP("trivy", "scan.scanner.id")
	trivyReport.SetP("Trivy", "scan.scanner.name")
	trivyReport.SetP("https://github.com/aquasecurity/trivy/", "scan.scanner.url")
	trivyReport.SetP("Aqua Security", "scan.scanner.vendor.name")
	trivyReport.SetP(trivyVersion(), "scan.scanner.version")

	trivyReport.SetP(startScanTime, "scan.start_time")
	trivyReport.SetP(endScanTime, "scan.end_time")

	if err := analyzer.Convert(trivyReport); err != nil {
		return err
	}

	outPath := valueOrDefault(
		options.Global().ReportPath,
		filepath.Join(dir, "output"),
	)

	if err := os.MkdirAll(outPath, os.ModePerm); err != nil {
		return err
	}

	reportFile := filepath.Join(outPath, fmt.Sprintf("trivy-%s-report.json", analyzer.Meta().Id))
	if err := os.WriteFile(reportFile, trivyReport.Bytes(), os.ModePerm); err != nil {
		return err
	}

	if err := os.Remove(trivyOutputFile); err != nil {
		return err
	}

	return nil
}

func formatTime(t time.Time) string {
	return t.Format(gitlabReportTimePattern)
}

func formattedMeasure(f func() error) (string, string, error) {
	start, end, err := measure(f)
	return formatTime(start), formatTime(end), err
}

func measure(f func() error) (time.Time, time.Time, error) {
	start := time.Now()
	err := f()
	end := time.Now()
	return start, end, err
}

func trivyVersion() string {
	if out, msg, err := piped(
		exec.Command("trivy", "-v"),
		exec.Command("grep", "Version"),
		exec.Command("awk", "FNR == 1 {print $2}"),
	); err != nil {
		log.Println(msg)
		return unknownVersion
	} else {
		return strings.TrimSuffix(out, "\n")
	}
}

func pluginVersion() string {
	if out, msg, err := piped(
		exec.Command("trivy", "plugin", "list"),
		exec.Command("awk", "$2 ~ /trivy-gitlab/ { getline;print $2 }"),
	); err != nil {
		log.Println(msg)
		return unknownVersion
	} else {
		return strings.TrimSuffix(out, "\n")
	}
}
