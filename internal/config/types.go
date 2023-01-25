package config

type FuzzTestType string

const (
	CPP    FuzzTestType = "cpp"
	JAVA   FuzzTestType = "java"
	KOTLIN FuzzTestType = "kotlin"
)

type GradleBuildLanguage string

const (
	G_GROOVY GradleBuildLanguage = "groovy"
	G_KOTLIN GradleBuildLanguage = "kotlin"
)

type Engine string

const (
	LIBFUZZER Engine = "libfuzzer"
)
