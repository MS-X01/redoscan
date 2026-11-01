# Contributing to redoscan

Thanks for helping make redoscan better. The most useful contributions, in order:

1. **A vulnerable regex it misses** (false negative) or a **safe one it flags** (false positive).
2. **A new vulnscan rule** for a pattern you see in real code.
3. Language / dialect improvements in the parser or extractor.

## Setup

```bash
git clone https://github.com/MS-X01/redoscan.git
cd redoscan
pip install -e ".[dev]"
pytest -q
```

## Adding a vulnscan rule

1. Add a `Rule(...)` to `src/redoscan/vulnscan.py` (category, CWE, severity, languages, pattern, title, fix).
2. Add a **vulnerable** line to `examples/vulnerable/<file>` and its **hardened twin** to `examples/safe/<file>`.
3. Add a test in `tests/test_vulnscan.py` asserting the vulnerable line fires and the safe one does not.
4. Keep the finding labelled `heuristic` unless it is backed by an actual proof.

## Pull requests

- Keep PRs focused; include tests.
- `pytest -q` must pass; `redoscan examples/safe --fail-on low --no-html-report` must stay clean.
- Describe what the change detects and any false-positive risk.
