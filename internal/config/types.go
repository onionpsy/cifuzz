package config

type FuzzTestType string

const (
	CPP    FuzzTestType = "cpp"
	Java   FuzzTestType = "java"
	Kotlin FuzzTestType = "kotlin"
)

type GradleBuildLanguage string

const (
	GradleGroovy GradleBuildLanguage = "groovy"
	GradleKotlin GradleBuildLanguage = "kotlin"
)

type Engine string

const (
	Libfuzzer Engine = "libfuzzer"
)
