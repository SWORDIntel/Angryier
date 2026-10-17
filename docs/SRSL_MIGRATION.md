# Angryier licensing migration — 2026-10-17

The first-party Angryier code in distributions adopting this revision is licensed under [SRSL-1.1](../LICENSE), a source-available (not OSI open-source) licence. The exact SRSL-1.0 text is preserved at [LICENSES/SRSL-1.0.txt](../LICENSES/SRSL-1.0.txt); prior valid grants for copies previously distributed under v1.0 remain effective.

The workspace-level Cargo metadata now references `LicenseRef-SRSL-1.1`, inherited by workspace crates. [The matching licence text](../LICENSES/LicenseRef-SRSL-1.1.txt) is supplied for tooling and review. Third-party crates, bundled engines, Intel XED, Z3 and any vendored libraries remain licensed under their own applicable terms.

Non-commercial purposes are explicitly defined, including independent defensive research. For-profit internal use and use of protected source as ML training material outside statutory exceptions require separate authorisation. Commercial rights require an executed agreement; 50% profit sharing remains a proposed commercial term, not automatic breach damages.

This is a licensing and package-metadata update; no binary runtime logic, execution gate, telemetry or compiler build settings are changed. Obtain legal review before relying on disputed licence conditions.
