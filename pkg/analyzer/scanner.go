package analyzer

import (
	"fmt"
	"os"
)

type fsScanner struct{}

func NewFsScanner() *fsScanner {
	return &fsScanner{}
}

func (a *fsScanner) ScanCmd(options Options) ([]string, error) {
	return []string{"fs", options.Target}, nil
}

type imageScanner struct{}

func NewImageScanner() *imageScanner {
	return &imageScanner{}
}

func (a *imageScanner) ScanCmd(options Options) ([]string, error) {
	target, err := resolveContainerTarget(options)
	if err != nil {
		return nil, err
	}

	return []string{"image", target}, nil
}

func resolveContainerTarget(options Options) (string, error) {
	target := options.Target
	if target != "" {
		return target, nil
	}

	imageName, err := extractImageName()
	if err != nil {
		return "", fmt.Errorf("failed to extract image name: %w", err)
	}
	return imageName, nil

}

func extractImageName() (string, error) {

	if value, ok := os.LookupEnv("TS_IMAGE"); ok {
		return value, nil
	}
	if value, ok := os.LookupEnv("DOCKER_IMAGE"); ok {
		return value, nil
	}

	applicationRepository, err := getApplicationRepository()
	if err != nil {
		return "", err
	}

	applicationTag, err := getApplicationTag()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s:%s", applicationRepository, applicationTag), nil
}

func getApplicationRepository() (string, error) {
	if value, ok := os.LookupEnv("CI_APPLICATION_REPOSITORY"); ok {
		return value, nil
	}

	return getDefaultApplicationRepository()
}

func getApplicationTag() (string, error) {

	if value, ok := os.LookupEnv("CI_APPLICATION_TAG"); ok {
		return value, nil
	}

	return getEnvOrError("CI_COMMIT_SHA")

}

func getDefaultApplicationRepository() (string, error) {

	registryImage, err := getEnvOrError("CI_REGISTRY_IMAGE")
	if err != nil {
		return "", err
	}

	commitRefSlug, err := getEnvOrError("CI_COMMIT_REF_SLUG")
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%s/%s", registryImage, commitRefSlug), nil
}

func getEnvOrError(key string) (string, error) {
	if value, ok := os.LookupEnv(key); ok {
		if value == "" {
			return "", fmt.Errorf("environment variable %s is empty but is required for execution", key)
		}
		return value, nil
	}
	return "", fmt.Errorf("none of the environment variables %s were found but are required for execution", key)
}
