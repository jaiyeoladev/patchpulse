.PHONY: install run scan check test lint docker

install:
	python -m venv .venv && . .venv/bin/activate && pip install -e ".[dev]"

run:
	python -m patchpulse serve --reload

scan:
	python -m patchpulse scan

check:
	python -m patchpulse check

test:
	pytest -q

lint:
	ruff check .

docker:
	docker compose up --build
