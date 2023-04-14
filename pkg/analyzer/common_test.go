package analyzer

import (
	"reflect"
	"testing"

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
			got := MakeLinks(tt.references)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("MakeLinks() = %v, want %v", got, tt.want)
			}
		})
	}
}
