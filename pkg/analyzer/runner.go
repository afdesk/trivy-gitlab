package analyzer

import (
	"bytes"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/Jeffail/gabs/v2"
)

const GitlabReportTimePattern = "2006-01-02T15:04:05"

func gitlabFormatTime() string {
	return time.Now().Format(GitlabReportTimePattern)
}

func Run(analyzer Analyzer) error {

	pwd, _ := os.Getwd()
	templateFile := filepath.Join(pwd, "templates", "report", analyzer.TemplateFileName())

	tempFile := filepath.Join(pwd, "temp.json")
	startTime := gitlabFormatTime()
	_, stderr, err := execTrivyCommand(
		analyzer.ScanCommand(tempFile, templateFile)...,
	)
	endTime := gitlabFormatTime()
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

	if err := os.WriteFile(analyzer.ReportFileName(), trivyReport.Bytes(), os.ModePerm); err != nil {
		return err
	}

	if err := os.Remove(tempFile); err != nil {
		return err
	}

	return nil
}

type Analyzer interface {
	ScanCommand(outputFileName, templateFile string) []string
	Convert(trivyReport *gabs.Container) error
	TemplateFileName() string
	ReportFileName() string
}

func execTrivyCommand(cmds ...string) (string, string, error) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd := exec.Command("trivy", cmds...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}
