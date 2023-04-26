package analyzer

import (
	"fmt"
	"log"
	"net/url"
	"os"
	"regexp"
	"strings"
)

var httpOrHttpsProtocol = regexp.MustCompile(`^https?://.+`)

func fixUrlWithSpace(u string) string {
	if spaceIndex := strings.Index(u, " "); spaceIndex != -1 {
		return u[:spaceIndex]
	}
	return u
}

func isHttpOrHttps(u string) bool {
	return httpOrHttpsProtocol.MatchString(u)
}

func isValidUrl(u string) bool {
	url, err := url.ParseRequestURI(u)
	if err != nil {
		log.Println(err)
		return false
	}
	return isHttpOrHttps(url.String())
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
