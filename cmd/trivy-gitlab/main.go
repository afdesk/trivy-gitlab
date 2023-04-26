package main

import (
	"context"
	"fmt"
	"os"

	"github.com/afdesk/trivy-gitlab/pkg/analyzer"
	"github.com/afdesk/trivy-go-plugin/pkg/common"
	"golang.org/x/exp/slices"
)

var availableArgs = []string{"--debug", "--target", "--artifact-dir", "--scan-type"}

func main() {

	globalOptions := &analyzer.Options{
		Debug: false,
	}

	pluginArgs, _ := common.RetrievePluginArguments(availableArgs)

	if len(pluginArgs) > 0 {
		debug := pluginArgs["--debug"]
		globalOptions.Debug = slices.Contains([]string{"true", "1", "y", "yes"}, debug)
		globalOptions.Target = pluginArgs["--target"]
		globalOptions.ArtifactDir = pluginArgs["--artifact-dir"]
	}

	secAnalyzer, err := analyzer.GetAnalyzer(pluginArgs["--scan-type"])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	ctx := context.Background()

	if err := analyzer.Run(ctx, secAnalyzer, globalOptions); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
