package analyzer

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsHttpOrHttps(t *testing.T) {
	assert.True(t, isHttpOrHttps("http://aomedia.googlesource.com/aom/+/94bcbfe76b0fd5b8ac03645082dc23a88730c949"))
	assert.True(t, isHttpOrHttps("https://aomedia.googlesource.com/aom/+/94bcbfe76b0fd5b8ac03645082dc23a88730c949"))
	assert.False(t, isHttpOrHttps("ftp://ftp.sco.com/pub/updates/OpenServer/SCOSA-2005.3/SCOSA-2005.3.txt"))
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
