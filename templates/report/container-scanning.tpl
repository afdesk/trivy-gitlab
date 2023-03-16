{{- /* Template copied from https://github.com/aquasecurity/trivy/blob/712f9eba35999cfa6ba982a620bdd4866e8f40a2/contrib/gitlab.tpl */ -}}
{
  "vulnerabilities": [
  {{- $t_first := true }}
  {{- range . }}
  {{- $target := .Target }}
    {{- range .Vulnerabilities -}}
    {{- if $t_first -}}
      {{- $t_first = false -}}
    {{ else -}}
      ,
    {{- end }}
    {
      "id": "{{ .VulnerabilityID }}",
      "category": "container_scanning",
      "message": "{{ printf "%s in %s-%s" .VulnerabilityID .PkgName .InstalledVersion }}",
      "description": {{ .Description | printf "%q" }},
      {{- /* cve is a deprecated key, use id instead */}}
      "cve": "{{ .VulnerabilityID }}",
      "severity": {{ if eq .Severity "UNKNOWN" -}}
                    "Unknown"
                  {{- else if eq .Severity "LOW" -}}
                    "Low"
                  {{- else if eq .Severity "MEDIUM" -}}
                    "Medium"
                  {{- else if eq .Severity "HIGH" -}}
                    "High"
                  {{- else if eq .Severity "CRITICAL" -}}
                    "Critical"
                  {{-  else -}}
                    "{{ .Severity }}"
                  {{- end }},
      {{- /* TODO: Define confidence */}}
      "confidence": "Unknown",
      "solution": {{ if .FixedVersion -}}
                    "Upgrade {{ .PkgName }} to {{ .FixedVersion }}"
                  {{- else -}}
                    "No solution provided"
                  {{- end }},
      "scanner": {
        "id": "trivy",
        "name": "trivy"
      },
      "location": {
        "dependency": {
          "package": {
            "name": "{{ .PkgName }}"
          },
          "version": "{{ .InstalledVersion }}"
        },
        {{- /* TODO: No mapping available - https://github.com/aquasecurity/trivy/issues/332 */}}
        "operating_system": "Unknown",
        "image": "{{ $target }}"
      },
      "identifiers": [
        {
	  {{- /* TODO: Type not extractable - https://github.com/aquasecurity/trivy-db/pull/24 */}}
          "type": "cve",
          "name": "{{ .VulnerabilityID }}",
          "value": "{{ .VulnerabilityID }}",
          "url": "{{ .PrimaryURL }}"
        }
      ],
      "links": [
        {{- $l_first := true -}}
        {{- range .References -}}
        {{- if $l_first -}}
          {{- $l_first = false }}
        {{- else -}}
          ,
        {{- end -}}
        {
          "url": "{{ . }}"
        }
        {{- end }}
      ]
    }
    {{- end -}}
  {{- end }}
  ],
  "remediations": [],
  "scan": {
    "scanner": {
      "id": "trivy",
      "name": "Trivy",
      "url": "https://github.com/aquasecurity/trivy/",
      "vendor": {
        "name": "Aqua Security"
      },
      "version": "0.38.3"
    },
    "analyzer": {
      "id": "trivy-gitlab",
      "name": "trivy-gitlab plguin",
      "vendor": {
        "name": "afdesk"
      }
    },
    "type": "container_scanning",
    "start_time": "",
    "end_time": "",
    "status": "success"
  }
}