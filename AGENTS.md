# Angryier Agent Guidelines

<!-- START: RELATIVE_PATHS_RULE -->
## Path Resolution Policy
> **CRITICAL RULE**: Never use absolute paths (e.g. `/home/...`, `/fast/home/...`).
> All paths must be strictly relative or dynamically resolved across all projects, configurations, code, scripts, subagents, and tools.
> Use relative paths (`./`, `../`), `PROJECT_ROOT`, `$(dirname ...)`, `Path(__file__)`, or dynamic environment variables with relative fallbacks.
<!-- END: RELATIVE_PATHS_RULE -->
