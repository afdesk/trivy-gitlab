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
            {{- range .Vulnerabilities -}}
                {{- if $t_first -}}
                    {{- $t_first = false -}}
                {{ else -}}
                    ,
                {{- end }}
                {
                    "id": "",
                    "name": "{{ .Title }}",
                    {{- /* TODO: Description is broken */}}
                    "description": "{{ .Title }}",
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
                            {{- /* TODO: Type not extractable - https://github.com/aquasecurity/trivy-db/pull/24 */}}
                            "type": "cve",
                            "name": "{{ .VulnerabilityID }}",
                            "value": "{{ .VulnerabilityID }}",
                            "url": "{{ .PrimaryURL }}"
                        }
                    ],
                    "location": {
                        "file": "{{ $target }}",
                        "dependency": {
                            "package": {
                                "name": "{{ .PkgName }}"
                            },
                            "version": "{{ .InstalledVersion }}"
                        }
                    },
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
            {{- end }}
         {{- end }}
    ],
    "dependency_files": [
        {{- $d_first := true }}
        {{- range . }}
             {{- if $d_first -}}
                {{- $d_first = false -}}
            {{ else -}}
                ,
            {{- end }}
            {{- $target := .Target }}
            {{- $type := .Type }}
            {
                "path": "{{ $target }}",
                "package_manager": "{{ $type }}",
                "dependencies": [
                    {{- $k_first := true }}
                    {{- range .Packages -}}
                        {{- if $k_first -}}
                            {{- $k_first = false -}}
                        {{ else -}}
                            ,
                        {{- end }}
                        {
                            "package": {
                                "name": {{ if .SrcName -}}
                                            "{{ .SrcName }}"
                                        {{- else -}}
                                            "{{ .Name }}"
                                         {{- end }}
                            },
                            "version": {{ if .SrcVersion -}}
                                            "{{ .SrcVersion }}"
                                        {{- else -}}
                                            "{{ .Version }}"
                                         {{- end }}
                        }
                    {{- end }}
                ]
            }
         {{- end }}
    ]
}