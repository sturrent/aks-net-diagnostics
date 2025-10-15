# Changelog

All notable changes to the AKS Network Diagnostics tool will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.1] - 2025-10-15

### Removed
- **Cache feature**: Removed development-only `--cache` flag and all caching functionality
  - Deleted `aks_diagnostics/cache.py` module (184 lines)
  - Deleted `tests/test_cache.py` test file (139 lines, 8 tests)
  - Removed cache references from main script and Azure CLI executor
  - Updated documentation to remove all cache references
  - **Rationale**: Cache was a development-only feature that could confuse end users expecting fresh diagnostic data

### Fixed
- **Honest error reporting**: Fixed fabricated cluster status error message
  - Changed misleading generic error to honest "error details not available" message
  - Tool now shows actual Azure error messages when available
  - **Impact**: Users get accurate error information for troubleshooting

### Changed
- **Test suite**: Reduced from 147 to 139 tests after cache removal (-8 cache tests)
- **Documentation**: Updated README.md and ARCHITECTURE.md to reflect simplified codebase

## [1.1.0] - 2025-10-13

### Changed

#### Breaking Changes
- **Renamed command-line flag**: Changed `--verbose` to `--details` for better clarity and consistency
- **IMPORTANT**: Scripts or automation using `--verbose` must be updated to use `--details`

#### Internal Improvements
- **Refactored internal APIs**: Function parameters renamed from `verbose` to `show_details` for consistency
- **Method naming**: Updated method names (`_print_verbose_report` → `_print_detailed_report`)
- **Code clarity**: Improved comments and variable names throughout codebase

#### Output Format Standardization
- **Consistent severity symbols**: Standardized all output to use uniform symbols:
  - `[X]` for Critical/Error issues
  - `[!]` for Warning issues
  - `[i]` for Informational findings
  - `[OK]` for Allow rules in NSG analysis
- **Fixed inconsistencies**: Corrected symbol usage in findings logs, NSG rule display, findings summary, and analyzer warnings

#### Documentation
- **Updated all examples**: README.md, CHANGELOG.md, and other documentation now use `--details` flag
- **Consistent terminology**: Changed references from "verbose mode" to "detailed mode" or "summary mode"

### Technical Details
- Modified files: 11 (7 Python modules, 4 documentation files)
- All 147 unit tests pass
- Tested on multiple real AKS clusters
- No functional logic changes, only naming and output format improvements

## [1.0.1] - 2025-10-03

### Changed

#### Documentation Improvements
- **Fixed emoji encoding issues**: Removed all emoji symbols to prevent rendering issues across platforms
- **Improved README structure**: Reordered sections for better user flow (Prerequisites → Installation → Quick Start)
- **Featured .pyz distribution**: Highlighted single-file distribution as the recommended method for end users
- **Removed redundant content**: Eliminated duplicate Contributing section from README (consolidated in CONTRIBUTING.md)
- **Cleaned up all markdown files**: Removed emojis from README.md, ARCHITECTURE.md, and CONTRIBUTING.md for professional, consistent presentation

#### GitHub Actions
- **Added automated release workflow**: Automatically builds and publishes .pyz file when version tags are pushed
- **Single-file distribution**: GitHub Releases now include the pre-built aks-net-diagnostics.pyz file (~57 KB)

### Fixed
- **Documentation rendering**: Fixed "�" symbols that appeared instead of emojis in some markdown viewers
- **User experience**: Quick Start section now properly appears after Prerequisites section

## [1.0.0] - 2025-10-03

### 🎉 Initial Release

First stable release of the AKS Network Diagnostics tool with comprehensive network analysis capabilities.

### Added

#### Core Features
- **Cluster Analysis**: Comprehensive read-only analysis of AKS cluster network configuration
- **Network Security Groups**: Validates NSG rules for AKS required traffic and inter-node communication
- **DNS Configuration**: Analyzes Azure DNS, custom DNS, and private DNS zones
- **Route Tables**: Detects User Defined Routes (UDR) that may break AKS management traffic
- **API Server Access**: Validates authorized IP ranges and access restrictions
- **Outbound Connectivity**: Analyzes LoadBalancer and NAT Gateway configurations
- **Active Connectivity Tests**: Optional VMSS-based probing for DNS resolution and HTTPS connectivity

#### Architecture
- **Modular Design**: 12 specialized analyzer modules with single responsibility
- **ClusterDataCollector**: Centralized data gathering from Azure
- **AzureCLIExecutor**: Azure CLI command execution with error handling
- **CacheManager**: Optional response caching for improved performance (opt-in with `--cache`)
- **InputValidator**: Security validation for all user inputs
- **MisconfigurationAnalyzer**: Correlates findings across analyzers for root cause analysis

#### Distribution
- **Single-File Distribution**: Python zipapp (.pyz) for easy deployment (~57 KB)
- **Modular Source**: Full source code available for development and customization
- **Automated Releases**: GitHub Actions workflow for building and publishing releases

#### Command-Line Options
- `--name, -n`: AKS cluster name (required)
- `--resource-group, -g`: Resource group name (required)
- `--subscription`: Azure subscription ID override
- `--probe-test`: Enable active connectivity testing from cluster nodes
- `--json-report`: Export findings to JSON file
- `--details`: Detailed console output
- `--cache`: Enable response caching for faster re-runs
- `--version`: Show version and exit

#### Testing
- **147 Unit Tests**: Comprehensive test coverage across all modules
- **Test Organization**: 9 test files covering analyzers, utilities, and data models
- **Mocking**: Full Azure CLI response mocking for isolated testing

#### Documentation
- **README.md**: User-focused installation and usage guide
- **ARCHITECTURE.md**: Technical architecture with Mermaid diagrams
- **CONTRIBUTING.md**: Developer contribution guidelines and processes
- **Mermaid Diagrams**: Visual architecture, data flow, and build process diagrams

#### Issue Detection
- Outbound IPs not in API server authorized ranges
- Default routes redirecting to firewall/NVA
- NSG rules blocking AKS required traffic (443, 9000, 123, 53)
- NSG rules blocking inter-node communication
- DNS resolution failures for Azure services
- HTTPS connectivity blocked by firewalls or SSL inspection
- Private DNS zone VNet link missing
- Custom DNS not forwarding to Azure DNS (168.63.129.16)
- Cluster operation failures with detailed error messages
- Node pool failures and misconfigurations

### Technical Details

**Codebase Statistics:**
- Main Script: 467 lines (orchestration)
- Total Modules: 16 files (5,000+ lines)
- Test Coverage: 147 tests (3.5s execution)
- Type Coverage: 100% (all functions have type hints)

**Performance:**
- Typical Analysis: 30-60 seconds
- With Cache: 15-30 seconds (subsequent runs)
- With --probe-test: +30-60 seconds

**Security:**
- Read-only operations only
- Input validation and sanitization
- Command injection protection
- No destructive operations possible
- Azure CLI command whitelist

### Dependencies

**Required:**
- Python 3.7+
- Azure CLI 2.0+
- Azure authentication (`az login`)
- Reader permissions on AKS cluster and network resources

**Optional:**
- pytest (for running tests)
- pytest-cov (for coverage reports)

### Credits

Developed for Azure Kubernetes Service network troubleshooting and diagnostics.

---

[1.0.0]: https://github.com/sturrent/aks-net-diagnostics/releases/tag/v1.0.0
