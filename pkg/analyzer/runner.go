package analyzer

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/aquasecurity/trivy/pkg/report/cyclonedx"
	trivy "github.com/aquasecurity/trivy/pkg/types"
	gitlab "gitlab.com/gitlab-org/security-products/analyzers/report/v3"
	"go.uber.org/zap"
	"golang.org/x/exp/slices"
)

type Env struct {
}

type ConverterMeta struct {
	ID            string
	ScanType      gitlab.Category
	TrivyScanner  string
	ReportVersion gitlab.Version
}

type Converter interface {
	Meta() ConverterMeta
	Convert(r *trivy.Report) (*gitlab.Report, error)
	Skip(o *Options, env Env) bool
}

type SecurityAnalyzer interface {
	ScanCmd(options Options) (string, error)
	Converters() []Converter
}

type Options struct {
	Target      string
	ArtifactDir string
	ScanAll     bool
	Debug       bool
	Scanners    []string
	CycloneDX   bool
}

const (
	scannerVendor = "Aqua Security"
	scannerURL    = "https://github.com/aquasecurity/trivy/"
	scannerID     = "trivy"
	scannerName   = "Trivy"

	analyzerVendor = "afdesk"
	analyzerURL    = "https://github.com/afdesk/trivy-gitlab"
	analyzerID     = "trivy-gitlab"
	analyzerName   = "trivy-gitlab"

	unknownVersion = "unknown"

	cyclonedxArtifactName = "trivy-cyclonedx-report.json"
)

var analyzerMetadata = gitlab.AnalyzerDetails{
	Vendor: gitlab.Vendor{Name: analyzerVendor},
	URL:    analyzerURL,
	ID:     analyzerID,
	Name:   analyzerName,
}

var scannerMetadata = gitlab.ScannerDetails{
	Vendor: gitlab.Vendor{Name: scannerVendor},
	URL:    scannerURL,
	ID:     scannerID,
	Name:   scannerName,
}

func Run(ctx context.Context, analyzer SecurityAnalyzer, options *Options) error {

	if len(options.Scanners) == 0 {
		return fmt.Errorf("no scanners specified")
	}

	logger, _ := zap.NewDevelopment()
	defer logger.Sync()
	sugar := logger.Sugar()

	startTime := gitlab.ScanTime(time.Now())

	sugar.Info("Running analyzer")
	scanCmd, err := analyzer.ScanCmd(*options)
	if err != nil {
		return err
	}
	f, err := scan(ctx, scanCmd, options)
	if err != nil {
		return err
	}
	endTime := gitlab.ScanTime(time.Now())
	defer f.Close()

	var trivyReport trivy.Report

	if json.NewDecoder(f).Decode(&trivyReport); err != nil {
		sugar.Errorf("Couldn't parse the Trivy report: %v\n", err)
		return err
	}

	trivyVersion := getTrivyVersion()

	if !options.CycloneDX {
		sugar.Infof("Skipping CycloneDX report")
	} else {
		cyclonedxPath := filepath.Join(options.ArtifactDir, cyclonedxArtifactName)
		if err := generateCycloneDXReport(ctx, cyclonedxPath, trivyReport); err != nil {
			return err
		}
	}

	sugar.Info("Creating reports")
	for _, converter := range analyzer.Converters() {

		converterId := converter.Meta().ID

		if !slices.Contains(options.Scanners, converter.Meta().TrivyScanner) || converter.Skip(options, Env{}) {
			sugar.Infof("Skipping %s", converterId)
			continue
		}

		sugar.Infof("Converting %s", converterId)
		gitlabReport, err := converter.Convert(&trivyReport)
		if err != nil {
			return err
		}

		gitlabReport.Scan.Analyzer = analyzerMetadata
		gitlabReport.Scan.Analyzer.Version = getPluginVersion()
		gitlabReport.Scan.Scanner = scannerMetadata
		gitlabReport.Scan.Scanner.Version = trivyVersion
		gitlabReport.Scan.Type = gitlab.Category(converter.Meta().ScanType)
		gitlabReport.Scan.StartTime = &startTime
		gitlabReport.Scan.EndTime = &endTime
		gitlabReport.Scan.Status = gitlab.StatusSuccess

		gitlabReport.Version = converter.Meta().ReportVersion

		artifactName := fmt.Sprintf("trivy-%s-report.json", converterId)
		artifactPath := filepath.Join(options.ArtifactDir, artifactName)

		artifactFile, err := os.OpenFile(artifactPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		if err != nil {
			return err
		}

		defer artifactFile.Close()

		enc := json.NewEncoder(artifactFile)

		if err := enc.Encode(gitlabReport); err != nil {
			return err
		}

		sugar.Infof("Report saved to %s", artifactPath)

	}

	return nil

}

func generateCycloneDXReport(ctx context.Context, path string, r trivy.Report) error {
	cyclonedxReport, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer cyclonedxReport.Close()
	log.Println("Generating CycloneDX report")
	writer := cyclonedx.NewWriter(cyclonedxReport, "ff")
	if err := writer.Write(r); err != nil {
		return err
	}
	log.Println("CycloneDX report saved to %s", path)
	return nil
}

func scan(ctx context.Context, cmd string, options *Options) (io.ReadCloser, error) {
	tmpFile, err := os.CreateTemp("", "trivy-report-*.json")

	if err != nil {
		return nil, err
	}

	defer tmpFile.Close()

	cmds := strings.Split(cmd, " ")
	cmds = append(cmds, "--format", "json", "--output", tmpFile.Name(), "--no-progress", "--list-all-pkgs")
	cmds = append(cmds, "--scanners", strings.Join(options.Scanners, ","))

	if options.Debug {
		cmds = append(cmds, "--offline-scan", "--skip-db-update")
	}

	if err := execute(ctx, "trivy", cmds); err != nil {
		return nil, err
	}

	return os.Open(tmpFile.Name())
}

func execute(ctx context.Context, name string, cmds []string) error {

	cmd := exec.CommandContext(ctx, name, cmds...)

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}

	if err := cmd.Start(); err != nil {
		return err
	}
	log.Printf("Start execute command: %s %s\n", name, strings.Join(cmds, " "))

	scanner := bufio.NewScanner(stderr)
	for scanner.Scan() {
		m := scanner.Text()
		fmt.Println(m)
	}
	return cmd.Wait()
}

func getTrivyVersion() string {
	if out, _, err := piped(
		exec.Command("trivy", "-v"),
		exec.Command("grep", "Version"),
		exec.Command("awk", "FNR == 1 {print $2}"),
	); err != nil {
		return unknownVersion
	} else {
		return strings.TrimSuffix(out, "\n")
	}
}

func getPluginVersion() string {
	if out, _, err := piped(
		exec.Command("trivy", "plugin", "list"),
		exec.Command("awk", "$2 ~ /trivy-gitlab/ { getline;print $2 }"),
	); err != nil {
		return unknownVersion
	} else {
		return strings.TrimSuffix(out, "\n")
	}
}
