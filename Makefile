.PHONY: install test selftest run mock replay verify clean

install:
	pip install --break-system-packages -r requirements.txt

test:
	python -m pytest -q

selftest:
	python -m gateway selftest

run:
	python -m gateway run --policy config/balanced.yaml --upstream mock --port 8080

mock:
	python scripts/mock_llm_server.py --port 8081

replay:
	python scripts/generate_sample_data.py
	python -m gateway replay samples/traffic.jsonl --quiet

verify:
	python -m gateway verify-audit samples/audit.sample.jsonl

clean:
	rm -rf audit .pytest_cache
	find . -name __pycache__ -type d -exec rm -rf {} +
