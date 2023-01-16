package api

type FuzzingRun struct {
	Name                    string                  `json:"name"`
	DisplayName             string                  `json:"display_name"`
	Status                  string                  `json:"status"`
	FuzzerRunConfigurations FuzzerRunConfigurations `json:"fuzzer_run_configurations"`
	FuzzTargetConfig        FuzzTargetConfig        `json:"fuzz_target_config"`
}

type FuzzTargetConfig struct {
	Name string `json:"name"`
	CAPI CAPI   `json:"c_api"`
}

type CAPI struct {
	API API `json:"api"`
}

type API struct {
	RelativePath string `json:"relative_path"`
}

type FuzzerRunConfigurations struct {
	Engine       string `json:"engine"`
	NumberOfJobs int64  `json:"number_of_jobs"`
}
