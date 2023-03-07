/*
List is adapted from https://github.com/npm/ci-detect

The ISC License

Copyright (c) npm, Inc.

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.
*/

package detect_ci

import "os"

func CIName() string {
	if os.Getenv("GERRIT_PROJECT") != "" {
		return "gerrit"
	}
	if os.Getenv("SYSTEM_TEAMFOUNDATIONCOLLECTIONURI") != "" {
		return "azure-pipelines"
	}
	if os.Getenv("BITRISE_IO") != "" {
		return "bitrise"
	}
	if os.Getenv("BUDDY_WORKSPACE_ID") != "" {
		return "buddy"
	}
	if os.Getenv("BUILDKITE") != "" {
		return "buildkite"
	}
	if os.Getenv("CIRRUS_CI") != "" {
		return "cirrus"
	}
	if os.Getenv("GITLAB_CI") != "" {
		return "gitlab"
	}
	if os.Getenv("APPVEYOR") != "" {
		return "appveyor"
	}
	if os.Getenv("CIRCLECI") != "" {
		return "circle-ci"
	}
	if os.Getenv("SEMAPHORE") != "" {
		return "semaphore"
	}
	if os.Getenv("DRONE") != "" {
		return "drone"
	}
	if os.Getenv("DSARI") != "" {
		return "dsari"
	}
	if os.Getenv("GITHUB_ACTIONS") != "" {
		return "github-actions"
	}
	if os.Getenv("TDDIUM") != "" {
		return "tddium"
	}
	if os.Getenv("SCREWDRIVER") != "" {
		return "screwdriver"
	}
	if os.Getenv("STRIDER") != "" {
		return "strider"
	}
	if os.Getenv("TASKCLUSTER_ROOT_URL") != "" {
		return "taskcluster"
	}
	if os.Getenv("JENKINS_URL") != "" {
		return "jenkins"
	}
	if os.Getenv("bamboo_planKey") != "" || os.Getenv("bamboo.buildKey") != "" {
		return "bamboo"
	}
	if os.Getenv("GO_PIPELINE_NAME") != "" {
		return "gocd"
	}
	if os.Getenv("HUDSON_URL") != "" {
		return "hudson"
	}
	if os.Getenv("WERCKER") != "" {
		return "wercker"
	}
	if os.Getenv("NETLIFY") != "" {
		return "netlify"
	}
	if os.Getenv("NOW_GITHUB_DEPLOYMENT") != "" {
		return "now-github"
	}
	if os.Getenv("GITLAB_DEPLOYMENT") != "" {
		return "now-gitlab"
	}
	if os.Getenv("BITBUCKET_DEPLOYMENT") != "" {
		return "now-bitbucket"
	}
	if os.Getenv("BITBUCKET_BUILD_NUMBER") != "" {
		return "bitbucket-pipelines"
	}
	if os.Getenv("NOW_BUILDER") != "" {
		return "now"
	}
	if os.Getenv("VERCEL_GITHUB_DEPLOYMENT") != "" {
		return "vercel-github"
	}
	if os.Getenv("VERCEL_GITLAB_DEPLOYMENT") != "" {
		return "vercel-gitlab"
	}
	if os.Getenv("VERCEL_BITBUCKET_DEPLOYMENT") != "" {
		return "vercel-bitbucket"
	}
	if os.Getenv("VERCEL_URL") != "" {
		return "vercel"
	}
	if os.Getenv("MAGNUM") != "" {
		return "magnum"
	}
	if os.Getenv("NEVERCODE") != "" {
		return "nevercode"
	}
	if os.Getenv("RENDER") != "" {
		return "render"
	}
	if os.Getenv("SAIL_CI") != "" {
		return "sail"
	}
	if os.Getenv("SHIPPABLE") != "" {
		return "shippable"
	}
	if os.Getenv("TEAMCITY_VERSION") != "" {
		return "teamcity"
	}
	if os.Getenv("CI_NAME") == "sourcehut" {
		return "sourcehut"
	}
	if os.Getenv("CI_NAME") == "codeship" {
		return "codeship"
	}
	if os.Getenv("CODEBUILD_SRC_DIR") != "" {
		return "aws-codebuild"
	}
	if os.Getenv("CI") == "woodpecker" {
		return "woodpecker"
	}

	// Adding more CI providers from https://github.com/watson/ci-info/blob/20fae89d2bdeb0e5dd70e6a9e8d2647764e6ff04/vendors.json
	if os.Getenv("APPCENTER_BUILD_ID") != "" {
		return "vs-app-center"
	}
	if os.Getenv("CI_XCODE_PROJECT") != "" {
		return "xcode-cloud"
	}
	if os.Getenv("XCS") != "" {
		return "xcode-server"
	}
	if os.Getenv("RELEASE_BUILD_ID") != "" {
		return "releasehub"
	}
	if os.Getenv("HARNESS_BUILD_ID") != "" {
		return "harness"
	}
	if os.Getenv("EAS_BUILD") != "" {
		return "expo"
	}
	if os.Getenv("CM_BUILD_ID") != "" {
		return "codemagic"
	}
	if os.Getenv("CF_BUILD_ID") != "" {
		return "codefresh"
	}

	// test travis after the others, since several CI systems mimic it
	if os.Getenv("TRAVIS") != "" {
		return "travis-ci"
	}

	// Google Cloud Build - it sets almost nothing
	if os.Getenv("BUILDER_OUTPUT") != "" {
		return "google-cloud-build"
	}

	if os.Getenv("CI") != "" {
		return "custom"
	}

	// Not a CI environment
	return ""
}

func IsCI() bool {
	return CIName() != ""
}
