package main

import (
	"context"
	"fmt"
	"os"

	"github.com/afdesk/trivy-gitlab/pkg/analyzer"
	"github.com/afdesk/trivy-go-plugin/pkg/common"
)

var (
	version       = "dev"
	availableArgs = []string{"--target", "--artifact-dir", "--scan-type"}
)

func main() {

	pluginArgs, _ := common.RetrievePluginArguments(availableArgs)

	globalOptions := &analyzer.Options{
		Target:      pluginArgs["--target"],
		ArtifactDir: pluginArgs["--artifact-dir"],
	}

	ctx := context.Background()

	scannerType := analyzer.ScannerType(pluginArgs["--scan-type"])
	if err := analyzer.Run(ctx, scannerType, globalOptions, version); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
