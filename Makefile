PYTHON ?= python3
VENV ?= .venv
BIN := $(VENV)/bin

.PHONY: help venv install lint format test check live clean build

help:
	@echo "install   create venv and install package + dev extras"
	@echo "lint      ruff check + ruff format --check"
	@echo "format    apply ruff format and autofixes"
	@echo "test      run the offline test suite"
	@echo "check     lint + test"
	@echo "live      run tests including network-backed ones"
	@echo "build     build sdist and wheel into dist/"

venv:
	$(PYTHON) -m venv $(VENV)

install: venv
	$(BIN)/pip install --upgrade pip
	$(BIN)/pip install -e ".[dev]"

lint:
	$(BIN)/ruff check .
	$(BIN)/ruff format --check .

format:
	$(BIN)/ruff check --fix .
	$(BIN)/ruff format .

test:
	$(BIN)/pytest

check: lint test

live:
	EMAILSCOPE_LIVE=1 $(BIN)/pytest -m live

build:
	$(BIN)/pip install --upgrade build
	$(BIN)/python -m build

clean:
	rm -rf build dist *.egg-info .pytest_cache .ruff_cache
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
