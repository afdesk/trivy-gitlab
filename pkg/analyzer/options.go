package analyzer

type GlobalOptions struct {
	Debug        bool
	ReportPath   string
	TemplatePath string
}

type WithGlobalOptions interface {
	Global() GlobalOptions
}
