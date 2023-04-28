package main

import (
	"context"
	"fmt"
	"os"

	"github.com/afdesk/trivy-gitlab/internal/analyzer"
	"github.com/afdesk/trivy-go-plugin/pkg/common"
)

var (
	version       = "dev"
	availableArgs = []string{"--artifact-dir"}
)

func main() {

	if common.IsHelp() || len(os.Args) == 1 {
		printHelp(availableArgs)
	}

	pluginArgs, restArgs := common.RetrievePluginArguments(availableArgs)

	globalOptions := &analyzer.Options{
		ArtifactDir: pluginArgs["--artifact-dir"],
	}

	ctx := context.Background()

	if err := analyzer.Analyze(ctx, restArgs, globalOptions, version); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func printHelp(availableArgs []string) {
	fmt.Println("Usage: trivy trivy-gitlab ...")
	os.Exit(0)
}
