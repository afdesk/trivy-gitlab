package analyzer

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/aquasecurity/trivy/pkg/report/cyclonedx"
	trivy "github.com/aquasecurity/trivy/pkg/types"
	gitlab "gitlab.com/gitlab-org/security-products/analyzers/report/v3"
	"go.uber.org/zap"
	"golang.org/x/exp/slices"
)

type ConverterMeta struct {
	ID            string
	ScanType      gitlab.Category
	TrivyScanner  string
	ReportVersion gitlab.Version
}

type Converter interface {
	Meta() ConverterMeta
	Convert(r *trivy.Report) (*gitlab.Report, error)
}

type SecurityAnalyzer interface {
	ScanCmd(options Options) ([]string, error)
	Converters() []Converter
	ResolveScanners(scanners []string) []string
}

type Options struct {
	Target      string
	ArtifactDir string
	Debug       bool
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

	tsCyclonedxEnv = "TS_CYCLONEDX"
	tsScannersEnv  = "TS_SCANNERS"
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

var defaultScanners = []string{"vuln", "secret", "config"}

func Run(ctx context.Context, analyzer SecurityAnalyzer, options *Options) error {

	logger, err := zap.NewDevelopment()
	if err != nil {
		return err
	}

	defer func() {
		// ignore EINVAL and ENOTTY
		// https://github.com/uber-go/zap/issues/772
		// https://github.com/uber-go/zap/issues/991
		if err := logger.Sync(); err != nil && (!errors.Is(err, syscall.ENOTTY) || !errors.Is(err, syscall.EINVAL)) {
			log.Printf("failed to sync logger %v", err)
		}
	}()

	sugar := logger.Sugar()

	startTime := gitlab.ScanTime(time.Now())

	sugar.Info("Running analyzer")
	scanCmd, err := analyzer.ScanCmd(*options)
	if err != nil {
		return err
	}

	scanners := defaultScanners
	if val := os.Getenv(tsScannersEnv); val != "" {
		scanners = strings.Split(val, ",")
		fmt.Println("scanners: ", scanners)
	}

	scanners = analyzer.ResolveScanners(scanners)

	if len(scanners) == 0 {
		log.Println("Please specify at least one scanner. Set the TS_SCANNERS environment variable to a comma-separated list of scanners.")
		log.Println("Valid scanners are: vuln, secret, misconfig")
		return fmt.Errorf("no scanners specified")
	}

	scanCmd = append(scanCmd, "--scanners", strings.Join(scanners, ","))

	f, err := scan(ctx, scanCmd, options)
	if err != nil {
		return err
	}

	endTime := gitlab.ScanTime(time.Now())
	defer func() {
		if err := f.Close(); err != nil {
			sugar.Errorf("Couldn't close the Trivy report: %v\n", err)
		}
	}()

	trivyReport, err := parseTrivyReport(f)
	if err != nil {
		return err
	}

	trivyVersion := getTrivyVersion()

	if val := os.Getenv(tsCyclonedxEnv); val == "false" || val == "0" {
		sugar.Infof("Skipping CycloneDX report")
	} else {
		cyclonedxPath := filepath.Join(options.ArtifactDir, cyclonedxArtifactName)
		if err := generateCycloneDXReport(ctx, cyclonedxPath, trivyReport, trivyVersion); err != nil {
			return err
		}
	}

	sugar.Info("Creating reports")
	for _, converter := range analyzer.Converters() {

		converterId := converter.Meta().ID

		if !slices.Contains(scanners, converter.Meta().TrivyScanner) {
			sugar.Infof("Skipping %s", converterId)
			continue
		}

		sugar.Infof("Converting %s", converterId)
		gitlabReport, err := converter.Convert(&trivyReport)
		if err != nil {
			return fmt.Errorf("failed to convert %s report: %w", converterId, err)
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

		defer func() {
			if err := artifactFile.Close(); err != nil {
				sugar.Errorf("Couldn't close the %s report: %v\n", converterId, err)
			}
		}()

		enc := json.NewEncoder(artifactFile)
		if err := enc.Encode(gitlabReport); err != nil {
			return fmt.Errorf("failed to encode %s report: %w", converterId, err)
		}

		sugar.Infof("Report saved to %s", artifactPath)

	}

	return nil

}

func parseTrivyReport(r io.Reader) (trivy.Report, error) {
	var trivyReport trivy.Report
	if err := json.NewDecoder(r).Decode(&trivyReport); err != nil {
		return trivyReport, fmt.Errorf("failed to decode Trivy report: %w", err)
	}
	return trivyReport, nil
}

func generateCycloneDXReport(ctx context.Context, path string, r trivy.Report, version string) error {
	cyclonedxReport, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to open CycloneDX report: %w", err)
	}
	defer func() {
		if err := cyclonedxReport.Close(); err != nil {
			log.Printf("failed to close CycloneDX report: %v", err)
		}
	}()

	log.Println("Generating CycloneDX report")

	writer := cyclonedx.NewWriter(cyclonedxReport, version)
	if err := writer.Write(r); err != nil {
		return fmt.Errorf("failed to write CycloneDX report: %w", err)
	}

	log.Printf("CycloneDX report saved to %s", path)

	return nil
}

func scan(ctx context.Context, cmd []string, options *Options) (io.ReadCloser, error) {
	tmpFile, err := os.CreateTemp("", "trivy-report-*.json")

	if err != nil {
		return nil, err
	}

	defer func() {
		if err := tmpFile.Close(); err != nil {
			log.Printf("failed to close temporary file: %v", err)
		}
		if err := os.Remove(tmpFile.Name()); err != nil {
			log.Printf("failed to remove temporary file: %v", err)
		}
	}()

	cmds := append(cmd, "--format", "json", "--output", tmpFile.Name(), "--no-progress", "--list-all-pkgs")

	if options.Debug {
		cmds = append(cmds, "--offline-scan", "--skip-db-update")
	}

	if err := execute(ctx, "trivy", cmds); err != nil {
		return nil, fmt.Errorf("failed to execute trivy: %w", err)
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
	return getVersion(
		exec.Command("trivy", "-v", "--format", "json"),
		exec.Command("jq", "-r", ".Version"),
	)
}

func getPluginVersion() string {
	return getVersion(
		exec.Command("trivy", "plugin", "list"),
		exec.Command("awk", "$2 ~ /trivy-gitlab/ { getline;print $2 }"),
	)
}

func getVersion(cmds ...*exec.Cmd) string {
	if out, _, err := piped(cmds...); err != nil {
		return unknownVersion
	} else {
		if out == "" {
			return unknownVersion
		}
		return strings.TrimSuffix(out, "\n")
	}
}
