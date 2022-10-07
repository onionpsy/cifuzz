<div align="center">
  <img src="/docs/assets/logo.png" alt="Code Intelligence" />
  <h1>cifuzz</h1>
  <p>makes fuzz tests as easy as unit tests</p>
  <a href="https://github.com/CodeIntelligenceTesting/cifuzz/releases">
    <img src="https://img.shields.io/github/v/release/CodeIntelligenceTesting/cifuzz">
  </a>
  <a href="https://github.com/CodeIntelligenceTesting/cifuzz/actions/workflows/pipeline_pr.yml">
    <img src="https://img.shields.io/github/workflow/status/CodeIntelligenceTesting/cifuzz/PR%20Pipeline?logo=github" />
  </a>
  <a href="https://github.com/CodeIntelligenceTesting/cifuzz/blob/main/CONTRIBUTING.md">
    <img src="https://img.shields.io/badge/PRs-welcome-brightgreen.svg" />
  </a>
  <a href="https://github.com/CodeIntelligenceTesting/cifuzz/blob/main/LICENSE">
    <img src="https://img.shields.io/github/license/CodeIntelligenceTesting/cifuzz" />
  </a>

  <br />
  <br />

  <a href="https://docs.code-intelligence.com/cifuzz-cli" target="_blank">Docs</a>
  |
  <a href="https://github.com/CodeIntelligenceTesting/cifuzz/blob/main/docs/Glossary.md">Glossary</a>
  |
  <a href="https://github.com/CodeIntelligenceTesting/cifuzz/tree/main/examples">Examples</a>
  |
  <a href="https://www.code-intelligence.com/" target="_blank">Website</a>
  |
  <a href="https://www.code-intelligence.com/blog" target="_blank">Blog</a>
  |
  <a href="https://twitter.com/CI_Fuzz" target="_blank">Twitter</a>
  |
  <a href="https://www.youtube.com/channel/UCjXN5ac3tgXgtuCoSnQaEmA" target="_blank">YouTube</a>
</div>

---
> **_IMPORTANT:_** This project is under active development.
Be aware that the behavior of the commands or the configuration
can change.

## What is cifuzz
**cifuzz** is a CLI tool that helps you to integrate and run fuzzing
based tests into your project.

### Features
* Easily setup, create and run fuzz tests 
* Get coverage reports
* Manage your findings with ease
* Integrates into your favorite IDE
* Supports multiple programming languages and build systems

![CLion](/docs/assets/tools/clion.png)
![IDEA](/docs/assets/tools/idea.png)
![VSCode](/docs/assets/tools/vscode.png)
![C++](/docs/assets/tools/cpp.png)
![Java](/docs/assets/tools/java.png)
![CMake](/docs/assets/tools/cmake.png)
![gradle](/docs/assets/tools/gradle.png)
![Maven](/docs/assets/tools/maven.png)


## Installation
If you are new to the world of fuzzing, we recommend you to take a
look at our [Glossary](docs/Glossary.md) and our 
[example projects](examples/).


You can get the latest release [here](https://github.com/CodeIntelligenceTesting/cifuzz/releases/latest)
or by running our install script:

```bash
sh -c "$(curl -fsSL https://raw.githubusercontent.com/CodeIntelligenceTesting/cifuzz/main/install.sh)"
```

If you are using Windows you can download the [latest release](https://github.com/CodeIntelligenceTesting/cifuzz/releases/latest/download/cifuzz_installer_windows.exe) 
and execute it.

By default, cifuzz gets installed in your home directory under `cifuzz`.
You can customize the installation directory with `./cifuzz_installer -i /target/dir`.

Do not forget to add the installation directory to your `PATH`.


### Prerequisites

Depending on our language / build system of choice **cifuzz** has
different prerequisites:

<details>
 <summary>C/C++ (with CMake)</summary>

* [CMake >= 3.16](https://cmake.org/)
* [LLVM >= 11](https://clang.llvm.org/get_started.html)

**Ubuntu / Debian**
<!-- when changing this, please make sure it is in sync with the E2E pipeline -->
```bash
sudo apt install cmake clang llvm
```

**Arch**
<!-- when changing this, please make sure it is in sync with the E2E pipeline -->
```bash
sudo pacman -S cmake clang llvm
```

**MacOS**
<!-- when changing this, please make sure it is in sync with the E2E pipeline -->
```bash
brew install cmake llvm
```

**Windows**
<!-- when changing this, please make sure it is in sync with the E2E pipeline -->
<!-- clang is included in the llvm package --->
At least Visual Studio 2022 version 17 is required.
```bash
choco install cmake llvm
```
</details>

<details>
 <summary>Java with Maven</summary>
 TODO 
</details>

<details>
 <summary>Java with Gradle</summary>
 TODO 
</details>

## Getting started

**cifuzz** commands will interactively guide you through the needed
options and show next steps. You can find a complete
list of the available commands with all supported options and
parameters by calling `cifuzz command --help` or
[here](https://github.com/CodeIntelligenceTesting/cifuzz/wiki/cifuzz).

1. To initialize your project with cifuzz just execute `cifuzz init`
in the root directory of your project. This will create a file named
`cifuzz.yaml` containing the needed configuration and print out any
necessary steps to setup your project.

2. The next step is to create a fuzz test. Execute `cifuzz create`
and follow the instructions given by the command. This will create a
stub for your fuzz test, lets say it is called `my_fuzz_test_1.cpp` and
tell you how to integrate it into your project. You will find more detailed
information in our [Tutorial](docs/How-To-Write-A-Fuzz-Test.md).

3. Edit `my_fuzz_test_1.cpp` so it actually calls the function you want
to test with the input generated by the fuzzer. To learn more about
writing fuzz tests you can take a look at our
[Tutorial](docs/How-To-Write-A-Fuzz-Test.md) or one of the
[example projects](examples).

4. Start the fuzzing by executing `cifuzz run my_fuzz_test_1`.
**cifuzz** now tries to build the fuzz test and starts a fuzzing run.

### Generate coverage report

Once you executed a fuzz test, you can generate a coverage report which
shows the line by line coverage of the fuzzed code:

    cifuzz coverage my_fuzz_test_1

See [here](docs/Coverage-ide-integrations.md) for instructions on how to
generate and visualize coverage reports right from your IDE.

### Regression testing

**Important:** In general there are two ways to run your fuzz test:

1. An actual fuzzing run by calling: `cifuzz run my_fuzz_test_1`.
The fuzzer will rapidly generate new inputs and feed them into your
fuzz test. Any input that covers new parts of the fuzzed project will
be added to the generated corpus. cifuzz will run until a crash occurs
and report detailed information about the finding.

2. As a regression test, by invoking it through your IDE/editor or by
directly executing the replayer binary
(see [here](docs/How-To-Write-A-Fuzz-Test.md#regression-test--replayer)
on how to build that binary).
This will use the replayer to apply existing input data from the
seed corpus, which has to be stored in the directory
`<fuzz-test-name>_inputs` beside your fuzz test. Note that this
directory has to be created manually. In case a crash was found, the
directory will be created and the crashing input
is added to this directory automatically.
The fuzz test will stop immediately after
applying all inputs or earlier if a regression occurs.


### Sandboxing

On Linux, **cifuzz** runs the fuzz tests in a sandbox by default, to
avoid the fuzz test accidentally harming the system, for example by
deleting files or killing processes. It uses [Minijail](https://google.github.io/minijail/minijail0.1.html) for
that.

If you experience problems when running fuzz tests via **cifuzz** and
you don't expect your fuzz tests to do any harm to the system (or you're
already running **cifuzz** in a container), you might want to disable
the sandbox via the `--use-sandbox=false` flag or the
[`use-sandbox: false` config file setting](docs/Configuration.md#use-sandbox).

## Intro to cifuzz (live stream)
Check out [@jochil](https://github.com/jochil)'s live session for a walkthrough of how to get started with cifuzz. The event is freely accessible on YouTube and Linkedin. Click [here](https://www.code-intelligence.com/webinar/uncovering-hidden-bugs-and-vulnerabilities) for more info.

## Contributing
Want to help improve cifuzz? Check out our [contributing documentation](CONTRIBUTING.md).
There you will find instructions for building the tool locally.

If you find an issue, please report it on the issue tracker.
