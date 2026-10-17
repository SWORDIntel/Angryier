# Angryier Agent Guidelines

<!-- START: RELATIVE_PATHS_RULE -->
## Path Resolution Policy
- **Development & Design Phase**: Absolute paths (e.g., `/home/john/...`) and standard tool pathing are fully permitted.
- **Appliance Deployment Tooling**: Code and scripts intended for deployment inside the Proxmox VM (VM 9212 / appliance runtime) should use dynamic resolution (`Path(__file__).resolve().parent`, `$(dirname "$0")`, or relative paths) to ensure portability across VM environments.
<!-- END: RELATIVE_PATHS_RULE -->
