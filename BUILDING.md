# Build and verify

```bash
python -m pip install setuptools wheel
python verify.py
```

`verify.py` runs unittest regressions, compilation, demo assertions, builds a wheel and installs that wheel into a new temporary environment with no index/runtime dependency resolution. It exercises installed success and error cases from outside the source directory. CI additionally installs the source with standard build isolation and imports it from /tmp. Only development/build tooling needs a package index. No external registry publication.
