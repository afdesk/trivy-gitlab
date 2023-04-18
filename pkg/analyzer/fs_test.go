package analyzer

import "testing"

func TestParseBlameOutput(t *testing.T) {
	out := `819d0739a1374eb09e199bfc95182c8e1db66475 2 2 1
author Nikita Pivkin
author-mail ***
author-time 1681712851
author-tz +0600
committer Nikita Pivkin
committer-mail ***
committer-time 1681712851
committer-tz +0600
summary tests(fixture): add .env
filename dev/tests/fixtures/rep1/.env
`

	tests := []struct {
		name    string
		out     string
		want    *BlameOutput
		wantErr bool
	}{
		{
			name: "valid output",
			out:  out,
			want: &BlameOutput{
				Sha:           "819d0739a1374eb09e199bfc95182c8e1db66475",
				Committer:     "Nikita Pivkin",
				Summary:       "tests(fixture): add .env",
				CommitterTime: "2023-04-17 06:27:31 +0000 UTC",
			},
			wantErr: false,
		},
		{
			name:    "empty output",
			out:     "",
			want:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseBlameOutput(tt.out)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseBlameOutput() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != nil && tt.want != nil {
				if got.Sha != tt.want.Sha {
					t.Errorf("parseBlameOutput() got.Sha = %v, want %v", got.Sha, tt.want.Sha)
				}
				if got.Committer != tt.want.Committer {

					t.Errorf("parseBlameOutput() got.Committer = %v, want %v", got.Committer, tt.want.Committer)
				}
				if got.Summary != tt.want.Summary {
					t.Errorf("parseBlameOutput() got.Summary = %v, want %v", got.Summary, tt.want.Summary)
				}
				if got.CommitterTime != tt.want.CommitterTime {
					t.Errorf("parseBlameOutput() got.CommitterTime = %v, want %v", got.CommitterTime, tt.want.CommitterTime)
				}
			}
		})
	}
}
