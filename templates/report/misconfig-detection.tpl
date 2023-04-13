{
  "version": "",
  "scan": {
    "scanner": {
      "id": "",
      "name": "",
      "url": "",
      "vendor": {
        "name": ""
      }
    },
    "analyzer": {
      "id": "",
      "name": "",
      "vendor": {
        "name": ""
      }
    },
    "type": "",
    "start_time": "",
    "end_time": "",
    "status": "success"
  },
   "vulnerabilities": [
    {{- $t_first := true }}
    {{- range . }}
        {{- $target := .Target }}
        {{- range .Misconfigurations -}}
            {{- if $t_first -}}
                {{- $t_first = false -}}
            {{ else -}}
                    ,
            {{- end }}
            {
                "id": "{{ .ID }}",
                "name": "{{ .Title }}",
                "description": "{{ .Description }}",
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
                "solution": "{{ .Resolution }}",
                "identifiers": [
                    {
                        "type": "{{ .Type }}",
                        "name": "{{ .ID }}",
                        "value": "{{ .ID }}"
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
                ],
                "location": {
                    "file": "{{ $target }}",
                    "start_line": "{{ .CauseMetadata.StartLine }}",
                    "end_line": "{{ .CauseMetadata.EndLine }}"
                }
            }
        {{- end -}}
    {{- end }}
    ]
}
