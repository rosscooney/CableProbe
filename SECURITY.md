# Security Policy

## Reporting a vulnerability

If you believe you have found a security vulnerability in CableProbe, please
report it privately. **Do not open a public GitHub issue for security
vulnerabilities.**

Preferred options:

1. **GitHub private vulnerability reporting** — use the "Report a vulnerability"
   button under the repository's *Security* tab (GitHub → Security → Advisories).
2. **Email** — `<SECURITY-CONTACT-TO-BE-CONFIGURED>`
   (placeholder: replace with a monitored security contact address for
   Stable State Consulting Ltd before publishing the repository).

Please include:

- a description of the issue and its impact,
- steps to reproduce or a proof of concept,
- affected version(s) or commit hash,
- any suggested remediation.

## What to expect

- Acknowledgement of your report as soon as reasonably possible.
- An assessment of the issue and, where accepted, a fix or mitigation.
- Credit in the release notes if you would like it.

## Scope

CableProbe is a defensive analysis tool that runs on a sacrificial host and only
observes, records and reports. Relevant reports include, for example: code that
could cause CableProbe to modify the system under test, unsafe handling of
report data, or command-injection via crafted device metadata.

CableProbe does not attempt to prove that a cable is safe or uncompromised, and
"CableProbe failed to detect a malicious cable" is not by itself a
vulnerability — though improvements to detection coverage are very welcome as
normal issues or pull requests.
