# crossfire docs

- [installation.md](installation.md) sets up Node, the detector toolchain, and the two agent CLIs, then walks a dry run that proves the install without spending a token.
- [usage.md](usage.md) is the reference: every command and flag, every config field with its type and default, the repro convention, and worked examples from a stubbed run up to a real one with the supplemental passes on.
- [architecture.md](architecture.md) explains why the broker holds control, what each module owns, and what each design decision costs. Read it before changing the loop.
- [troubleshooting.md](troubleshooting.md) maps the error strings crossfire actually prints back to the thing that caused them.
- [../CONTRIBUTING.md](../CONTRIBUTING.md) covers the dev loop, the commit style this repo already uses, and what a change has to clear before it lands.
