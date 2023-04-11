package analyzer

import (
	"context"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Jeffail/gabs/v2"
)

const GitlabReportTimePattern = "2006-01-02T15:04:05"
const UnknownVersion = "unknown"

type Analyzer[O any] interface {
	ScanCommand(outputFileName, templateFile string, options O) []string
	Convert(trivyReport *gabs.Container) error
	SchemaVersion() string
	TemplateFileName() string
	ReportFileName() string
}

func Run[O WithGlobalOptions](ctx context.Context, getAnalyzer func() (Analyzer[O], error), options O) error {

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
		filepath.Join(dir, "templates", "report", analyzer.TemplateFileName()),
	)

	tempFile := filepath.Join(dir, "temp.json")
	startTime := formattedTime()
	_, stderr, err := execute(
		ctx, "trivy", analyzer.ScanCommand(tempFile, templateFile, options),
	)
	endTime := formattedTime()
	if err != nil {
		log.Println(stderr)
		return err
	}

	trivyReport, err := gabs.ParseJSONFile(tempFile)
	if err != nil {
		return err
	}

	// common properties
	trivyReport.Set(analyzer.SchemaVersion(), "version")
	trivyReport.SetP(pluginVersion(), "scan.analyzer.version")
	trivyReport.SetP(trivyVersion(), "scan.scanner.version")
	trivyReport.SetP(startTime, "scan.start_time")
	trivyReport.SetP(endTime, "scan.end_time")

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

	reportFile := filepath.Join(outPath, analyzer.ReportFileName())
	if err := os.WriteFile(reportFile, trivyReport.Bytes(), os.ModePerm); err != nil {
		return err
	}

	if err := os.Remove(tempFile); err != nil {
		return err
	}

	return nil
}

func trivyVersion() string {
	if out, msg, err := piped(
		exec.Command("trivy", "-v"),
		exec.Command("grep", "Version"),
		exec.Command("awk", "FNR == 1 {print $2}"),
	); err != nil {
		log.Println(msg)
		return UnknownVersion
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
		return UnknownVersion
	} else {
		return strings.TrimSuffix(out, "\n")
	}
}

func formattedTime() string {
	return time.Now().Format(GitlabReportTimePattern)
}
