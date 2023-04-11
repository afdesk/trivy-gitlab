package analyzer

import (
	"bytes"
	"context"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/Jeffail/gabs/v2"
)

const GitlabReportTimePattern = "2006-01-02T15:04:05"

func formattedTime() string {
	return time.Now().Format(GitlabReportTimePattern)
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
	_, stderr, err := execTrivyCommand(
		ctx, analyzer.ScanCommand(tempFile, templateFile, options),
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
	trivyReport.Set("14.1.2", "version")               // TODO schema version, move it to the analyzer?
	trivyReport.SetP("0.0.1", "scan.analyzer.version") // TODO version of our plugin
	trivyReport.SetP("0.0.1", "scan.scanner.version")  // TODO trivy version
	trivyReport.SetP(startTime, "scan.start_time")
	trivyReport.SetP(endTime, "scan.end_time")

	if err := analyzer.Convert(trivyReport); err != nil {
		return err
	}

	outPath := valueOrDefault(
		options.Global().ReportPath,
		filepath.Join(dir, "output"),
	)

	log.Println(outPath)

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

type Analyzer[O any] interface {
	ScanCommand(outputFileName, templateFile string, options O) []string
	Convert(trivyReport *gabs.Container) error
	TemplateFileName() string
	ReportFileName() string
}

func execTrivyCommand(ctx context.Context, cmds []string) (string, string, error) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "trivy", cmds...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

func valueOrDefault(val, def string) string {
	if val == "" {
		return def
	}

	return val
}
