package analyzer

import (
	"reflect"
	"testing"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"
	"gitlab.com/gitlab-org/security-products/analyzers/report/v3"
)

func TestMakeLinks(t *testing.T) {
	tests := []struct {
		name       string
		references []string
		want       []report.Link
	}{
		{
			name:       "no references",
			references: []string{},
			want:       []report.Link{},
		},
		{
			name:       "one reference",
			references: []string{"https://example.com"},
			want: []report.Link{
				{
					URL: "https://example.com",
				},
			},
		},
		{
			name:       "multiple references",
			references: []string{"https://example.com", "https://example.com/2"},
			want: []report.Link{
				{
					URL: "https://example.com",
				},
				{
					URL: "https://example.com/2",
				},
			},
		},
		{
			name:       "invalid reference",
			references: []string{"https://example.com", "ftp://ftp.sco.com/pub/updates/OpenServer/SCOSA-2005.3/SCOSA-2005.3.txt"},
			want: []report.Link{
				{
					URL: "https://example.com",
				},
			},
		},
		{
			name:       "invalid reference with space",
			references: []string{"https://example.com", "https://example.com/2 (v1.0.2)"},
			want: []report.Link{
				{
					URL: "https://example.com",
				},
				{
					URL: "https://example.com/2",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := makeLinks(tt.references)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("MakeLinks() = %v, want %v", got, tt.want)
			}
		})
	}
}

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

func TestIsHttpOrHttps(t *testing.T) {
	if res := isHttpOrHttps("http://aomedia.googlesource.com/aom/+/94bcbfe76b0fd5b8ac03645082dc23a88730c949"); res != true {
		t.Errorf("isHttpOrHttps() = %v, want %v", res, true)
	}

	if res := isHttpOrHttps("https://aomedia.googlesource.com/aom/+/94bcbfe76b0fd5b8ac03645082dc23a88730c949"); res != true {
		t.Errorf("isHttpOrHttps() = %v, want %v", res, true)
	}

	if res := isHttpOrHttps("ftp://ftp.sco.com/pub/updates/OpenServer/SCOSA-2005.3/SCOSA-2005.3.txt"); res != false {
		t.Errorf("isHttpOrHttps() = %v, want %v", res, false)
	}
}

func TestFixUrlWithSpace(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want string
	}{
		{
			name: "test 1",
			url:  "https://aomedia.googlesource.com/aom/+/94bcbfe76b0fd5b8ac03645082dc23a88730c949 (v2.0.1)",
			want: "https://aomedia.googlesource.com/aom/+/94bcbfe76b0fd5b8ac03645082dc23a88730c949",
		},
		{
			name: "test 2",
			url:  "https://aomedia.googlesource.com/aom/+/94bcbfe76b0fd5b8ac03645082dc23a88730c949",
			want: "https://aomedia.googlesource.com/aom/+/94bcbfe76b0fd5b8ac03645082dc23a88730c949",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := fixUrlWithSpace(tt.url); got != tt.want {
				t.Errorf("fixUrlWithSpace() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsValidUrl(t *testing.T) {

	tests := []struct {
		name string
		url  string
		want bool
	}{
		{
			name: "invalid url",
			url:  "https://aomedia.googlesource.com/aom/+/94bcbfe76b0fd5b8ac03645082dc23a88730c949 (v2.0.1)",
			want: true,
		},
		{
			name: "invalid url",
			url:  "ftp://ftp.sco.com/pub/updates/OpenServer/SCOSA-2005.3/SCOSA-2005.3.txt",
			want: false,
		},
		{
			name: "valid url",
			url:  "https://aomedia.googlesource.com/aom/+/94bcbfe76b0fd5b8ac03645082dc23a88730c949",
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isValidUrl(tt.url); got != tt.want {
				t.Errorf("isValidUrl() = %v, want %v", got, tt.want)
			}
		})
	}
}
