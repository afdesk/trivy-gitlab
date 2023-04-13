package analyzer

import (
	"testing"

	"github.com/Jeffail/gabs/v2"
	"github.com/stretchr/testify/assert"
)

func TestLineNumbers(t *testing.T) {

	vuln, err := gabs.ParseJSON([]byte(`{
		"location": {
			"start_line": "1",
			"end_line": "2"
		}
	}`))
	if err != nil {
		t.Error(err)
	}

	FixLineNumbers(vuln)

	test := func(path string, expected int) {
		line, ok := vuln.Path(path).Data().(int)
		if !ok {
			t.Error()
		}
		if line != expected {
			t.Fatalf(`%s = %d, want %d`, path, line, expected)
		}
	}

	test("location.start_line", 1)
	test("location.end_line", 2)
}

func TestFixLinks(t *testing.T) {
	vuln, err := gabs.ParseJSON([]byte(`{
		"links": [
                {
                    "url": "https://blog.trailofbits.com/2023/02/16/suid-logic-bug-linux-readline/ (v2.0.1)"
                }
            ]
	}`))
	if err != nil {
		t.Error(err)
	}

	FixLinks(vuln)

	url, ok := vuln.Path("links.0.url").Data().(string)
	if !ok {
		t.Error("url is not string")
	}
	expectedUrl := "https://blog.trailofbits.com/2023/02/16/suid-logic-bug-linux-readline/"
	if url != expectedUrl {
		t.Fatalf(`links.0.url = %s, want %s`, url, expectedUrl)
	}
}

func TestFixLinksShouldRemoveInvalidUrl(t *testing.T) {
	vuln, err := gabs.ParseJSON([]byte(`{
		"links": [
                {
                    "url": "ftp://ftp.netbsd.org/pub/NetBSD/security/advisories/NetBSD-SA2004-006.txt.asc"
                }
            ]
	}`))
	if err != nil {
		t.Error(err)
	}

	FixLinks(vuln)

	if size := len(vuln.S("links").Children()); size != 0 {
		t.Fatalf(`the number of links must be equal to 0, but equals %d`, size)
	}
}

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

func TestExtractImageAndOs(t *testing.T) {
	test := func(image string, expectedImage string, expectedOs string) {
		img, os, _ := extractImageAndOs(image)

		if img != expectedImage {
			t.Errorf("Expected image %s but got %s", expectedImage, img)
		}

		if os != expectedOs {
			t.Errorf("Expected os %s but got %s", expectedOs, os)
		}
	}

	test("alpine:3.7 (alpine 3.7)", "alpine:3.7", "alpine 3.7")
	test("alpine:3.7", "", "")
	test("alpine (alpine 3.7)", "alpine:latest", "alpine 3.7")
	test("alpine", "", "")
}

func TestFixImageAndOs(t *testing.T) {
	vuln, err := gabs.ParseJSON([]byte(`{
		"location": {
			"dependency": {
				"package": { "name": "util-linux" },
				"version": "2.36.1-8+deb11u1"
			},
			"image": "python (debian 11.6)",
			"operating_system": "Unknown"
		}
	}`))
	if err != nil {
		t.Error(err)
	}

	FixImageAndOs(vuln)

	test := func(path string, expected string) {
		actual, ok := vuln.Path(path).Data().(string)
		if !ok {
			t.Error()
		}
		if actual != expected {
			t.Fatalf(`%s = %s, want %s`, path, actual, expected)
		}
	}

	test("location.image", "python:latest")
	test("location.operating_system", "debian 11.6")
}
