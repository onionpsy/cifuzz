# Installation Guide

## Installation Directories

### Linux/MacOS

Executing the installation as a **user**, files will be installed to

* `~/.local/share/cifuzz` (default) or
* `$XDG_DATA_HOME/cifuzz` if set.

The `cifuzz` executable will be installed to `~/.local/bin`.

Installing **cifuzz** with **root**, files will be installed to
`/opt/code-intelligence/cifuzz` and the executable to `/usr/local/bin`.

### Windows

All files will be installed to `%APPDATA%/cifuzz` with the executable located in `%APPDATA%/cifuzz/bin`.

## How to uninstall cifuzz

### Version < 0.7.0

If you installed cifuzz into the default directory as **root**:

```bash
sudo rm -rf ~/cifuzz /usr/local/share/cifuzz
```

If you installed cifuzz as **non-root**:

```bash
rm -rf ~/cifuzz ~/.cmake/packages/cifuzz
```

If you installed into a custom installation directory you have to remove that one instead.

### Version >= 0.7.0

From this version on the installation directory is fixed.

If you installed cifuzz as **root**:

```bash
sudo rm -rf /opt/code-intelligence/cifuzz /usr/local/bin/cifuzz /usr/local/share/cifuzz
```

If you installed cifuzz as **non-root**:

```bash
rm -rf "${XDG_DATA_HOME:-$HOME/.local/share}/cifuzz" ~/.local/bin/cifuzz ~/.cmake/packages/cifuzz
```

If you installed cifuzz on **Windows**:

```bash
rd /s %APPDATA%/cifuzz
```

To delete the registry entries on **Windows**:

```bash
reg delete "HKLM\Software\Kitware\CMake\Packages\cifuzz" /f 2> nul
reg delete "HKCU\Software\Kitware\CMake\Packages\cifuzz" /f 2> nul
```
