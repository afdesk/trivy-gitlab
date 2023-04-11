package main

import (
	"fmt"
	"os"

	"github.com/afdesk/trivy-gitlab/pkg/analyzer"
	"github.com/spf13/cobra"
)

func main() {
	rootCmd := NewRootCommand()

	globalOptions := &analyzer.GlobalOptions{}
	rootCmd.PersistentFlags().BoolVar(&globalOptions.Debug, "debug", false, "debug mode")
	rootCmd.PersistentFlags().StringVar(&globalOptions.ReportPath, "report-path", "", "report path")
	rootCmd.PersistentFlags().StringVar(&globalOptions.TemplatePath, "template-path", "", "template-path")

	rootCmd.AddCommand(
		ContainerScanningCommand(globalOptions),
		DependencyScanningCommand(globalOptions),
		SecretDetectCommand(globalOptions),
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

func ContainerScanningCommand(options *analyzer.GlobalOptions) *cobra.Command {

	return &cobra.Command{
		Use:   "container IMAGE_NAME",
		Short: "Container scanning",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return analyzer.Run(
				cmd.Context(),
				func() (analyzer.Analyzer[analyzer.ContainerOptions], error) {
					return analyzer.NewContainerAnalyzer(args[0])
				},
				analyzer.ContainerOptions{GlobalOptions: *options},
			)
		},
	}
}

func DependencyScanningCommand(options *analyzer.GlobalOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "dependency",
		Short: "Dependency scanning",
		RunE: func(cmd *cobra.Command, args []string) error {
			return fmt.Errorf("not implemented")
		},
	}
}

func SecretDetectCommand(options *analyzer.GlobalOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "secret",
		Short: "Secret scanning",
		RunE: func(cmd *cobra.Command, args []string) error {
			return fmt.Errorf("not implemented")
		},
	}
}
