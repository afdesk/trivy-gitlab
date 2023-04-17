package main

import (
	"fmt"
	"os"

	"github.com/afdesk/trivy-gitlab/pkg/analyzer"
	"github.com/spf13/cobra"
)

func main() {
	rootCmd := NewRootCommand()

	globalOptions := &analyzer.Options{}
	rootCmd.PersistentFlags().BoolVar(&globalOptions.Debug, "debug", false, "Debug mode")
	rootCmd.PersistentFlags().StringVar(&globalOptions.Target, "target", "", "Target")
	rootCmd.PersistentFlags().StringVar(&globalOptions.ArtifactDir, "artifact-dir", "", "Artifact directory")

	rootCmd.AddCommand(
		ContainerScanningCommand(globalOptions),
		FsScanningCommand(globalOptions),
	)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func NewRootCommand() *cobra.Command {
	return &cobra.Command{}
}

func FsScanningCommand(options *analyzer.Options) *cobra.Command {
	return &cobra.Command{
		Use:   "fs PATH",
		Short: "Container scanning",
		RunE: func(cmd *cobra.Command, args []string) error {
			return analyzer.Run(cmd.Context(), analyzer.NewFsAnalyzer(), options)
		},
	}
}

func ContainerScanningCommand(options *analyzer.Options) *cobra.Command {

	return &cobra.Command{
		Use:   "container IMAGE_NAME",
		Short: "Container scanning",
		RunE: func(cmd *cobra.Command, args []string) error {
			return analyzer.Run(cmd.Context(), analyzer.NewImageAnalyzer(), options)
		},
	}
}
