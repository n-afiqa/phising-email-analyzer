# Tests and linting

Install the test and lint tools if they are not already available:

```powershell
python -m pip install pytest ruff
```

Run the test suite and lint checks from the project folder:

```powershell
python -m pytest
python -m ruff check src tests
```
