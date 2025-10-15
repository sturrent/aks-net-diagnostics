# Documentation Directory

This directory contains documentation for the AKS Network Diagnostics tool, organized by topic.

## 📁 Directory Structure

```
docs/
├── README.md (this file)
├── ORGANIZATION_SUMMARY.md
├── DOCUMENTATION_UPDATE_SUMMARY.md
└── migration/
    ├── README.md
    ├── AZURE_CLI_ARCHITECTURE.md
    ├── AZURE_SDK_REFACTORING.md
    ├── PHASE3_COMPLETION_SUMMARY.md
    ├── PHASE4_PROGRESS_SUMMARY.md
    ├── SNAKE_CASE_NORMALIZATION_FIX.md
    ├── STATUS_REPORT.md
    └── TEST_MIGRATION_GUIDE.md
```

## 📚 Documentation Categories

### Root Documentation (Repository Root)
Essential documentation for all users:
- **[README.md](../README.md)** - Getting started, usage, features
- **[CHANGELOG.md](../CHANGELOG.md)** - Version history and changes
- **[CONTRIBUTING.md](../CONTRIBUTING.md)** - Contribution guidelines
- **[ARCHITECTURE.md](../ARCHITECTURE.md)** - Technical architecture overview

### Migration Documentation (`migration/`)
Historical documentation about the Azure CLI to SDK migration:
- **[README.md](migration/README.md)** - Migration overview
- **[AZURE_CLI_ARCHITECTURE.md](migration/AZURE_CLI_ARCHITECTURE.md)** - Original Azure CLI implementation details
- **[AZURE_SDK_REFACTORING.md](migration/AZURE_SDK_REFACTORING.md)** - Migration methodology and approach
- **[PHASE3_COMPLETION_SUMMARY.md](migration/PHASE3_COMPLETION_SUMMARY.md)** - Unit test migration completion
- **[PHASE4_PROGRESS_SUMMARY.md](migration/PHASE4_PROGRESS_SUMMARY.md)** - Integration testing and bugs fixed
- **[SNAKE_CASE_NORMALIZATION_FIX.md](migration/SNAKE_CASE_NORMALIZATION_FIX.md)** - Fixing snake_case to camelCase conversion
- **[STATUS_REPORT.md](migration/STATUS_REPORT.md)** - Complete migration status
- **[TEST_MIGRATION_GUIDE.md](migration/TEST_MIGRATION_GUIDE.md)** - Guide for migrating tests

### Repository Organization (`docs/`)
Documentation about the repository structure and cleanup:
- **[ORGANIZATION_SUMMARY.md](ORGANIZATION_SUMMARY.md)** - Repository cleanup and organization
- **[DOCUMENTATION_UPDATE_SUMMARY.md](DOCUMENTATION_UPDATE_SUMMARY.md)** - Documentation changes summary

## 🎯 Quick Navigation

### For Users
- **Getting Started**: See [../README.md](../README.md)
- **Understanding the Tool**: See [../ARCHITECTURE.md](../ARCHITECTURE.md)
- **Contributing**: See [../CONTRIBUTING.md](../CONTRIBUTING.md)

### For Developers
- **Migration History**: See [migration/README.md](migration/README.md)
- **Technical Details**: See [migration/AZURE_SDK_REFACTORING.md](migration/AZURE_SDK_REFACTORING.md)
- **Bug Fixes**: See [migration/PHASE4_PROGRESS_SUMMARY.md](migration/PHASE4_PROGRESS_SUMMARY.md)

### For Maintainers
- **Repository Organization**: See [ORGANIZATION_SUMMARY.md](ORGANIZATION_SUMMARY.md)
- **Documentation Changes**: See [DOCUMENTATION_UPDATE_SUMMARY.md](DOCUMENTATION_UPDATE_SUMMARY.md)

## 📝 Note

This is the **Azure SDK migration branch** (`azure-sdk-migration`). The migration documentation in this directory represents the complete journey from Azure CLI subprocess calls to native Azure SDK usage, including all challenges, solutions, and lessons learned.

For the current production version (Azure CLI implementation), see the `main` branch.
