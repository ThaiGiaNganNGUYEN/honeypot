.PHONY: test run demo report

PY ?= python3

test:
	$(PY) -m unittest discover -s tests -t . -v

run:
	$(PY) -m honeypot

demo:
	$(PY) -m honeypot.demo

report:
	$(PY) -m honeypot.analyze
