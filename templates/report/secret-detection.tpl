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
            {{- range .Secrets -}}
                {{- if $t_first -}}
                    {{- $t_first = false -}}
                {{ else -}}
                        ,
                {{- end }}
                {
                    "id": "",
                    "name": "{{ .Title }}",
                    "description": "{{ .RuleID }}: {{ .Title }}",
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
                    "identifiers": [
                        {
                            "type": "secret",
                            "name": "{{ .Title }}",
                            "value": "{{ .Title }}"
                        }
                    ],
                    "location": {
                        "file": "{{ $target }}",
                        "commit": {
                            "sha": "TODO"
                        },
                        "start_line": "{{ .StartLine }}",
                        "end_line": "{{ .EndLine }}"
                    },
                    "raw_source_code_extract": "{{ .Match }}"
                }
            {{- end }}
        {{- end }}
    ]
}