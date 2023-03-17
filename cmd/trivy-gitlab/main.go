package main

import (
	"fmt"
	"os"

	"github.com/afdesk/trivy-gitlab/pkg/analyzer"
	"github.com/spf13/cobra"
)

func main() {
	rootCmd := NewRootCommand()
	rootCmd.AddCommand(
		ContainerScanningCommand(),
		DependencyScanningCommand(),
		SecretDetectCommand(),
	)
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func NewRootCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "",
		Short: "",
	}
}

func ContainerScanningCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "container IMAGE_NAME",
		Short: "Container scanning",
		RunE: func(cmd *cobra.Command, args []string) error {
			containerAnalyzer, err := analyzer.NewContainerAnalyzer()
			if err != nil {
				return err
			}
			return analyzer.Run(containerAnalyzer)
		},
	}
}

func DependencyScanningCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "dependency",
		Short: "Dependency scanning",
		RunE: func(cmd *cobra.Command, args []string) error {
			return fmt.Errorf("not implemented")
		},
	}
}

func SecretDetectCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "secret",
		Short: "Secret scanning",
		RunE: func(cmd *cobra.Command, args []string) error {
			return fmt.Errorf("not implemented")
		},
	}
}
