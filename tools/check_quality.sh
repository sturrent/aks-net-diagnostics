#!/bin/bash

# Color codes for output
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Exit codes tracker
EXIT_CODE=0

echo -e "${CYAN}Running code quality checks for aks-net-diagnostics...${NC}"

# Black - code formatter check
echo -e "\n${YELLOW}=== Running Black (code formatter check) ===${NC}"
black --check --line-length 120 .
if [ $? -ne 0 ]; then
    echo -e "  ${RED}Black found formatting issues. Run 'black .' to fix.${NC}"
    EXIT_CODE=1
else
    echo -e "  ${GREEN}Black: PASSED${NC}"
fi

# isort - import sorter check
echo -e "\n${YELLOW}=== Running isort (import sorter check) ===${NC}"
isort --check-only --profile black .
if [ $? -ne 0 ]; then
    echo -e "  ${RED}isort found import issues. Run 'isort .' to fix.${NC}"
    EXIT_CODE=1
else
    echo -e "  ${GREEN}isort: PASSED${NC}"
fi

# Flake8 - PEP8 style check
echo -e "\n${YELLOW}=== Running Flake8 (PEP8 style check) ===${NC}"
flake8 --config=.flake8 .
if [ $? -ne 0 ]; then
    echo -e "  ${RED}Flake8: FAILED${NC}"
    EXIT_CODE=1
else
    echo -e "  ${GREEN}Flake8: PASSED${NC}"
fi

# Pylint - code quality check
echo -e "\n${YELLOW}=== Running Pylint (code quality check) ===${NC}"
pylint --rcfile=pylintrc aks_diagnostics/ aks-net-diagnostics.py
PYLINT_EXIT=$?
if [ $PYLINT_EXIT -eq 0 ]; then
    echo -e "  ${GREEN}Pylint: PASSED (10.0/10)${NC}"
else
    echo -e "  ${YELLOW}Pylint: Check score above (target: 9.5/10)${NC}"
fi

# Pytest - run tests
echo -e "\n${YELLOW}=== Running Tests ===${NC}"
pytest -v
if [ $? -ne 0 ]; then
    echo -e "  ${RED}Tests: FAILED${NC}"
    EXIT_CODE=1
else
    echo -e "  ${GREEN}Tests: PASSED${NC}"
fi

echo -e "\n${CYAN}=====================================${NC}"
echo -e "${CYAN}All quality checks complete!${NC}"
echo -e "${CYAN}=====================================${NC}"

exit $EXIT_CODE
