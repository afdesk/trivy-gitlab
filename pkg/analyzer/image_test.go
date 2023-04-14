package analyzer

import (
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
