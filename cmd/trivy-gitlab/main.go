package main

import (
	"fmt"
	"os"

	"github.com/afdesk/trivy-gitlab/pkg/analyzer"
	"github.com/afdesk/trivy-gitlab/pkg/analyzer/container"
	"github.com/afdesk/trivy-gitlab/pkg/analyzer/fs"
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
		MisconfigDetectCommand(globalOptions),
	)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func NewRootCommand() *cobra.Command {
	return &cobra.Command{}
}

func ContainerScanningCommand(options *analyzer.GlobalOptions) *cobra.Command {

	return &cobra.Command{
		Use:   "container IMAGE_NAME",
		Short: "Container scanning",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return analyzer.Run(
				cmd.Context(),
				func() (analyzer.Analyzer[container.ContainerOptions], error) {
					return container.NewContainerAnalyzer(args[0])
				},
				container.ContainerOptions{GlobalOptions: *options},
			)
		},
	}
}

func DependencyScanningCommand(options *analyzer.GlobalOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "dependency",
		Short: "Dependency scanning",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return analyzer.Run(
				cmd.Context(),
				func() (analyzer.Analyzer[fs.DependencyOptions], error) {
					return fs.NewDependencyAnalyzer(args[0]), nil
				},
				fs.DependencyOptions{GlobalOptions: *options},
			)
		},
	}
}

func SecretDetectCommand(options *analyzer.GlobalOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "secret",
		Short: "Secret scanning",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return analyzer.Run(
				cmd.Context(),
				func() (analyzer.Analyzer[fs.SecretOptions], error) {
					return fs.NewSecretAnalyzer(args[0]), nil
				},
				fs.SecretOptions{GlobalOptions: *options},
			)
		},
	}
}

func MisconfigDetectCommand(options *analyzer.GlobalOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "misconfig",
		Short: "Misconfig scanning",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return analyzer.Run(
				cmd.Context(),
				func() (analyzer.Analyzer[fs.MisconfigOptions], error) {
					return fs.NewMisconfigAnalyzer(args[0]), nil
				},
				fs.MisconfigOptions{GlobalOptions: *options},
			)
		},
	}
}
