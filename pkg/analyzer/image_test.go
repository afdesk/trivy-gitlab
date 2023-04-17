package analyzer

import (
	"os"
	"testing"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestMakeImage(t *testing.T) {
	tests := []struct {
		name     string
		artifact string
		want     string
	}{
		{
			name:     "no tag",
			artifact: "alpine",
			want:     "alpine:latest",
		},
		{
			name:     "with tag",
			artifact: "alpine:3.12",
			want:     "alpine:3.12",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &types.Report{
				ArtifactName: tt.artifact,
			}
			if got := makeImage(r); got != tt.want {
				t.Errorf("makeImage() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMakeOperatingSystem(t *testing.T) {
	tests := []struct {
		name string
		r    *types.Report
		want string
	}{
		{
			name: "debian",
			r: &types.Report{
				Metadata: types.Metadata{
					OS: &ftypes.OS{
						Family: "debian",
						Name:   "buster",
					},
				},
			},
			want: "debian buster",
		},
		{
			name: "alpine",
			r: &types.Report{
				Metadata: types.Metadata{
					OS: &ftypes.OS{
						Family: "alpine",
						Name:   "3.12",
					},
				},
			},
			want: "alpine 3.12",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := makeOperatingSystem(tt.r); got != tt.want {
				t.Errorf("makeOperatingSystem() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExtractImageName(t *testing.T) {

	tests := []struct {
		name    string
		env     map[string]string
		want    string
		wantErr bool
	}{
		{
			name: "TS_IMAGE",
			env: map[string]string{
				"TS_IMAGE": "my-image:latest",
			},
			want: "my-image:latest",
		},
		{
			name: "DOCKER_IMAGE",
			env: map[string]string{
				"DOCKER_IMAGE": "my-image:latest",
			},
			want: "my-image:latest",
		},
		{
			name: "application repository",
			env: map[string]string{
				"CI_APPLICATION_REPOSITORY": "my-image",
				"CI_APPLICATION_TAG":        "latest",
			},
			want: "my-image:latest",
		},
		{
			name: "resolve application repository",
			env: map[string]string{
				"CI_REGISTRY_IMAGE":  "registry.gitlab.com/my-group/my-project",
				"CI_COMMIT_REF_SLUG": "develop",
				"CI_APPLICATION_TAG": "latest",
			},
			want: "registry.gitlab.com/my-group/my-project/develop:latest",
		},
		{
			name: "resolve application tag",
			env: map[string]string{
				"CI_APPLICATION_REPOSITORY": "my-image",
				"CI_COMMIT_SHA":             "1234567890",
			},
			want: "my-image:1234567890",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for k, v := range tt.env {
				os.Setenv(k, v)
			}

			got, err := extractImageName()
			if (err != nil) != tt.wantErr {
				t.Errorf("extractImageName() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("extractImageName() = %v, want %v", got, tt.want)
			}

			for k := range tt.env {
				os.Unsetenv(k)
			}
		})
	}
}
