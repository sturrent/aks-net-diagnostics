# Contributing to AKS Network Diagnostics

Thank you for your interest in contributing to AKS Network Diagnostics! This document provides guidelines and information for contributors.

## 🎯 Ways to Contribute

- **Bug Reports**: Found a bug? Open an issue with details and steps to reproduce
- **Feature Requests**: Have an idea? Open an issue describing the use case
- **Code Contributions**: Submit pull requests for bug fixes or new features
- **Documentation**: Improve README, code comments, or examples
- **Testing**: Add test cases or improve test coverage

## 🚀 Getting Started

### Prerequisites

- Python 3.7+
- Azure CLI 2.0+
- Git
- Azure subscription (for testing)

### Development Setup

```bash
# Fork and clone the repository
git clone https://github.com/YOUR-USERNAME/aks-net-diagnostics.git
cd aks-net-diagnostics

# Create a feature branch
git checkout -b feature/my-feature

# Make your changes
# ... edit files ...

# Run tests
pytest -v

# Commit changes
git add .
git commit -m "feat: Add my feature"

# Push to your fork
git push origin feature/my-feature
```

## 📋 Contribution Guidelines

### Code Style

- **Type Hints**: All function parameters and return values must have type annotations
- **Docstrings**: All public classes, methods, and functions must have docstrings
- **Naming**: Use descriptive names following Python conventions (snake_case for functions/variables, PascalCase for classes)
- **Line Length**: Maximum 120 characters per line
- **Imports**: Group imports (standard library, third-party, local modules)

Example:

```python
from typing import Dict, List, Optional

def analyze_configuration(cluster_name: str, resource_group: str) -> Dict[str, Any]:
    """
    Analyze cluster configuration.
    
    Args:
        cluster_name: Name of the AKS cluster
        resource_group: Resource group containing the cluster
        
    Returns:
        Dictionary containing analysis results
        
    Raises:
        ValueError: If cluster cannot be found
    """
    # Implementation
    pass
```

### Testing Requirements

- **Unit Tests**: All new code must include unit tests
- **Test Coverage**: Maintain or improve code coverage
- **Test Naming**: Use descriptive test names: `test_<method>_<scenario>_<expected_result>`
- **Test Isolation**: Tests must not depend on external resources or each other
- **Mocking**: Use `unittest.mock` for Azure CLI calls and external dependencies

Example test:

```python
def test_analyze_nsg_rules_when_blocking_rule_exists_returns_finding(self):
    """Test NSG analyzer detects blocking rules"""
    # Setup
    mock_nsg = {
        'rules': [{
            'name': 'DenyAll',
            'access': 'Deny',
            'priority': 100,
            'direction': 'Outbound'
        }]
    }
    self.mock_azure_cli.execute.return_value = mock_nsg
    
    # Execute
    analyzer = NSGAnalyzer(self.mock_azure_cli, self.cluster_info)
    result = analyzer.analyze()
    
    # Assert
    self.assertEqual(len(analyzer.get_findings()), 1)
    self.assertEqual(analyzer.get_findings()[0].code, FindingCode.NSG_BLOCKING)
```

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation changes
- `test:` Test additions or changes
- `refactor:` Code refactoring
- `perf:` Performance improvements
- `chore:` Build/tooling changes

Examples:

```
feat: Add Azure Firewall analyzer module
fix: Handle missing nodeResourceGroup in cluster info
docs: Update README with connectivity test examples
test: Add tests for route table analyzer
refactor: Extract data collection to separate module
```

### Pull Request Process

1. **Create an Issue**: For significant changes, create an issue first to discuss
2. **Fork & Branch**: Fork the repo and create a feature branch
3. **Make Changes**: Implement your changes with tests
4. **Run Tests**: Ensure all tests pass: `pytest -v`
5. **Update Documentation**: Update README.md if adding features
6. **Commit**: Use conventional commit messages
7. **Push**: Push to your fork
8. **Open PR**: Create pull request with clear description

### Pull Request Checklist

- [ ] Tests added/updated and passing (`pytest -v`)
- [ ] Code follows project style guidelines
- [ ] Type hints added for all functions
- [ ] Docstrings added for public methods
- [ ] Documentation updated (README.md, ARCHITECTURE.md if applicable)
- [ ] `.pyz` build tested (`python build_zipapp.py && python aks-net-diagnostics.pyz --help`)
- [ ] No breaking changes (or clearly documented if unavoidable)

## 🏗️ Building the Distribution

### Creating the Single-File Distribution

The project uses Python's `zipapp` module to create a single-file executable:

```bash
# Build the .pyz file
python build_zipapp.py

# Verify it works
python aks-net-diagnostics.pyz --help

# Test with actual cluster (if available)
python aks-net-diagnostics.pyz -n myCluster -g myRG
```

### Testing the .pyz File

Before submitting a PR that modifies core functionality:

```bash
# 1. Build the zipapp
python build_zipapp.py

# 2. Run unit tests on source code
pytest -v

# 3. Test the .pyz file functionality
python aks-net-diagnostics.pyz --help
python aks-net-diagnostics.pyz -n test-cluster -g test-rg  # If you have test resources

# 4. Verify file size is reasonable (~57 KB)
ls -lh aks-net-diagnostics.pyz  # Linux/macOS
Get-Item aks-net-diagnostics.pyz | Format-List Length  # Windows
```

### Release Process (Maintainers)

Releases are automated via GitHub Actions:

```bash
# 1. Update version in code (if applicable)
# 2. Commit all changes
git add .
git commit -m "chore: Prepare release v2.2.0"

# 3. Create and push tag
git tag -a v2.2.0 -m "Release version 2.2.0"
git push origin v2.2.0

# GitHub Actions will automatically:
# - Build aks-net-diagnostics.pyz
# - Run tests on the .pyz file
# - Create a GitHub Release
# - Attach the .pyz file to the release
```

The release workflow is defined in `.github/workflows/release.yml`.
- [ ] README.md updated (if adding user-facing features)
- [ ] Commit messages follow conventional commits format
- [ ] No merge conflicts with main branch

## 🏗️ Architecture Guidelines

### Adding a New Analyzer

New analyzers should:

1. **Inherit from BaseAnalyzer** (if applicable)
2. **Follow single responsibility principle**: One analyzer, one concern
3. **Use Azure CLI executor**: Never call Azure CLI directly
4. **Generate findings**: Use the Finding model for consistency
5. **Handle errors gracefully**: Catch exceptions and log appropriately

Structure:

```python
from aks_diagnostics.base_analyzer import BaseAnalyzer
from aks_diagnostics.models import Finding, FindingCode, Severity

class MyAnalyzer(BaseAnalyzer):
    """Analyzes specific aspect of AKS configuration."""
    
    def __init__(self, azure_cli, cluster_info):
        super().__init__(azure_cli, cluster_info)
        # Additional initialization
    
    def analyze(self) -> Dict[str, Any]:
        """
        Perform analysis.
        
        Returns:
            Dictionary with analysis results
        """
        try:
            # Fetch data
            data = self.azure_cli.execute(['some', 'command'])
            
            # Analyze
            if self._detect_issue(data):
                self.add_finding(Finding.create_error(
                    FindingCode.MY_ISSUE,
                    message="Issue detected",
                    recommendation="How to fix"
                ))
            
            return {"analyzed": True}
            
        except Exception as e:
            self.logger.error(f"Analysis failed: {e}")
            return {"analyzed": False, "error": str(e)}
    
    def _detect_issue(self, data: Dict[str, Any]) -> bool:
        """Private helper method."""
        # Implementation
        pass
```

### Module Organization

- **aks_diagnostics/**: All reusable modules
- **tests/**: Corresponding test files
- **Main script**: Orchestration only, no business logic

## 🐛 Reporting Bugs

### Before Submitting

1. Check if the bug is already reported in [Issues](https://github.com/sturrent/aks-net-diagnostics/issues)
2. Collect diagnostic information:
   - Python version: `python --version`
   - Azure CLI version: `az --version`
   - Operating system
   - Complete error message

### Bug Report Template

```markdown
**Describe the bug**
A clear description of what the bug is.

**To Reproduce**
Steps to reproduce the behavior:
1. Run command: `python aks-net-diagnostics.py -n cluster -g rg`
2. See error

**Expected behavior**
What you expected to happen.

**Actual behavior**
What actually happened.

**Environment:**
- OS: [e.g., Windows 11, Ubuntu 22.04]
- Python version: [e.g., 3.11.5]
- Azure CLI version: [e.g., 2.50.0]

**Additional context**
- Verbose output (if applicable)
- JSON report (if applicable)
```

## 💡 Feature Requests

### Before Submitting

1. Check if the feature is already requested
2. Consider if it fits the project scope (AKS network diagnostics)
3. Think about how it would work from a user perspective

### Feature Request Template

```markdown
**Is your feature request related to a problem?**
A clear description of the problem.

**Describe the solution you'd like**
What you want to happen.

**Describe alternatives you've considered**
Other approaches you've thought about.

**Additional context**
Examples, use cases, or screenshots.
```

## 🧪 Testing

### Running Tests

```bash
# Run all tests
pytest -v

# Run specific module tests
pytest tests/test_nsg_analyzer.py -v

# Run with coverage
pytest --cov=aks_diagnostics --cov-report=html

# Stop on first failure
pytest -x
```

### Writing Tests

- Place tests in `tests/` directory
- Name test files `test_<module>.py`
- Use descriptive test method names
- Mock Azure CLI calls
- Test both success and failure scenarios
- Test edge cases

## 📚 Documentation

### Code Documentation

- All public classes and methods must have docstrings
- Use Google-style docstrings
- Include type hints in signatures
- Provide examples in docstrings for complex methods

### README Updates

When adding user-facing features:

- Add to "What It Analyzes" section
- Add usage example if applicable
- Update command options table if needed
- Add to architecture diagram/table if new module

## 📞 Contact

- **Issues**: [GitHub Issues](https://github.com/sturrent/aks-net-diagnostics/issues)
- **Discussions**: [GitHub Discussions](https://github.com/sturrent/aks-net-diagnostics/discussions)
- **Maintainer**: [@sturrent](https://github.com/sturrent)

## 📄 License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

Thank you for contributing to AKS Network Diagnostics! 🎉
