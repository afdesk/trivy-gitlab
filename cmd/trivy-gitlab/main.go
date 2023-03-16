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
		Args:  cobra.RangeArgs(0, 1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var imageName string
			if len(args) == 0 {
				imageName = os.Getenv("DOCKER_IMAGE") // TODO
				if imageName == "" {
					return fmt.Errorf("todo...")
				}
			} else {
				imageName = args[0]
			}
			return analyzer.Run(analyzer.NewContainerAnalyzer(imageName))
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
