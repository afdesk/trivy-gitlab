package analyzer

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/afdesk/trivy-go-plugin/pkg/common"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	trivy "github.com/aquasecurity/trivy/pkg/types"
	gitlab "gitlab.com/gitlab-org/security-products/analyzers/report/v3"
)

type ConverterMeta struct {
	ID            string
	ScanType      gitlab.Category
	ReportVersion gitlab.Version
}

type Converter interface {
	Meta() ConverterMeta
	Convert(r *trivy.Report) (*gitlab.Report, error)
}

type SecurityScanner interface {
	ScanCmd(options Options) ([]string, error)
}

type Options struct {
	Target      string
	ArtifactDir string
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

	trivyVersion = "0.39.1"

	tmpFileName = "trivy-tmp-report.json"
)

var analyzerMetadata = gitlab.AnalyzerDetails{
	Vendor: gitlab.Vendor{Name: analyzerVendor},
	URL:    analyzerURL,
	ID:     analyzerID,
	Name:   analyzerName,
}

var scannerMetadata = gitlab.ScannerDetails{
	Vendor:  gitlab.Vendor{Name: scannerVendor},
	URL:     scannerURL,
	ID:      scannerID,
	Name:    scannerName,
	Version: trivyVersion,
}

type ScannerType string

const (
	ContainerScannerType ScannerType = "container"
	FsScannerType        ScannerType = "fs"
)

func Run(ctx context.Context, scannerType ScannerType, options *Options, plguinVersion string) error {

	scanner, err := getScanner(scannerType)
	if err != nil {
		return err
	}

	startTime := gitlab.ScanTime(time.Now())

	log.Println("Running scanner")
	scanCmd, err := scanner.ScanCmd(*options)
	if err != nil {
		return err
	}

	f, err := scan(ctx, scanCmd, options)
	if err != nil {
		return err
	}
	defer func() {
		if err := f.Close(); err != nil {
			log.Printf("Couldn't close the Trivy report: %v\n", err)
		}
	}()

	endTime := gitlab.ScanTime(time.Now())
	trivyReport, err := parseTrivyReport(f)
	if err != nil {
		return err
	}

	log.Println("Creating reports")
	for _, converter := range getConverters(&trivyReport) {

		converterId := converter.Meta().ID

		log.Printf("Converting %s", converterId)
		gitlabReport, err := converter.Convert(&trivyReport)
		if err != nil {
			return fmt.Errorf("failed to convert %s report: %w", converterId, err)
		}

		gitlabReport.Scan.Analyzer = analyzerMetadata
		gitlabReport.Scan.Analyzer.Version = plguinVersion
		gitlabReport.Scan.Scanner = scannerMetadata
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
				log.Printf("Couldn't close the %s report: %v\n", converterId, err)
			}
		}()

		enc := json.NewEncoder(artifactFile)
		if err := enc.Encode(gitlabReport); err != nil {
			return fmt.Errorf("failed to encode %s report: %w", converterId, err)
		}

		log.Printf("Report saved to %s", artifactPath)
	}

	return nil
}

func getScanner(t ScannerType) (SecurityScanner, error) {
	switch t {
	case ContainerScannerType:
		return NewImageScanner(), nil
	case FsScannerType:
		return NewFsScanner(), nil
	default:
		return nil, fmt.Errorf("invalid scan type: %s", t)
	}
}

func getConverters(r *trivy.Report) []Converter {
	switch r.ArtifactType {
	case ftypes.ArtifactContainerImage:
		return []Converter{
			NewContainerConverter(),
			NewDependencyConverter(),
		}
	case ftypes.ArtifactFilesystem:
		return []Converter{
			NewDependencyConverter(),
			NewSecretsConverter(),
			NewMisconfigConverter(),
		}
	default:
		return []Converter{}
	}
}

func parseTrivyReport(r io.Reader) (trivy.Report, error) {
	var trivyReport trivy.Report
	if err := json.NewDecoder(r).Decode(&trivyReport); err != nil {
		return trivyReport, fmt.Errorf("failed to decode Trivy report: %w", err)
	}
	return trivyReport, nil
}

func scan(ctx context.Context, cmd []string, options *Options) (io.ReadCloser, error) {
	defer func() {
		if err := os.Remove(tmpFileName); err != nil {
			log.Printf("failed to remove temporary file: %v", err)
		}
	}()

	cmds := append(cmd, "--no-progress", "--list-all-pkgs")

	if err := common.MakeTrivyJsonReport(cmds, tmpFileName); err != nil {
		return nil, fmt.Errorf("failed to make trivy json report: %w", err)
	}

	return os.Open(tmpFileName)
}
