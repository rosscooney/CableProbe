# Contributing to CableProbe

Thanks for your interest in improving CableProbe. Contributions are welcome via
pull requests at <https://github.com/rosscooney/CableProbe>.

## Licensing of contributions

- CableProbe is distributed under the [MIT License](LICENSE).
- Contributions submitted to the project are expected to be distributed under
  the MIT License as part of CableProbe.
- Contributors retain copyright in their own contributions unless separately
  agreed in writing.
- By submitting a pull request, you confirm that you have the right to submit
  the code under the MIT License, and that you are licensing your contribution
  under the MIT License.

There is **no** Contributor Licence Agreement or copyright assignment to sign.

## What not to submit

- Proprietary or confidential code.
- Code copied from third-party projects under licences incompatible with MIT
  distribution (for example GPL/AGPL/SSPL source code copied into CableProbe).
- Significant new dependencies whose licences are incompatible with the
  project's MIT distribution model. If a change adds a new runtime dependency,
  note its licence in the pull request description.

CableProbe invokes some standard Linux command-line tools (for example `lsusb`,
`lsblk`, `journalctl`, `dmesg`) as separate, independently installed programs.
That is fine regardless of those tools' licences. Do not vendor their source
code into this repository.

## Scope and non-goals

CableProbe is a **defensive** observation tool. It observes, records and
reports. Please do not propose features that add payload injection,
exploitation, credential collection, persistence, remote access, HID attack
generation or similar offensive capability — such pull requests will be closed.

CableProbe cannot prove that a cable is safe or uncompromised; it gathers
evidence of *observable* behaviour. Keep documentation and output wording
consistent with that.

## Development setup

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pytest
```

## Before opening a pull request

- Add or update tests for behaviour changes.
- Run the test suite: `pytest`.
- Keep changes focused; describe the motivation in the PR description.
- Add the source-file header to any **new** original source files:

  ```python
  # Copyright (c) 2026 Stable State Consulting Ltd
  # SPDX-License-Identifier: MIT
  ```

## Reporting bugs and security issues

- Normal bugs: open a GitHub issue.
- Security vulnerabilities: please follow [SECURITY.md](SECURITY.md) and do not
  open a public issue.
