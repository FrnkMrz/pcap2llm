# Supported Environments

This page records the tested baseline for Python and TShark around the current
release line.

Related docs:

- [`DOCUMENTATION_MAP.md`](DOCUMENTATION_MAP.md)
- [`PROJECT_STATUS.md`](PROJECT_STATUS.md)
- [`REFERENCE.md`](REFERENCE.md)

## Python

CI currently tests:

- Python 3.11
- Python 3.12

## TShark

CI currently installs the Ubuntu package version of TShark available on `ubuntu-latest`.

This means:

- the project is regularly tested with one Linux-packaged TShark line in CI
- other TShark versions may work, but are not yet covered by a compatibility matrix

## Current Position

- Supported and verified: Python 3.11 and 3.12 in CI
- Regularly exercised: one CI-installed TShark version on Ubuntu
- Not yet broadly validated: cross-version TShark compatibility matrix across multiple distributions
