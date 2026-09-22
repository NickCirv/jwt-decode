# jwt-decode — command reference

[Overview](../README.md) · [Research record](RESEARCH.md)

Describes revision `8564b2ad95580ec5c5b644df786d35e92915453a`. Commands are source-inspected; no execution results are asserted.

## Workflow

Reads a token argument, stdin, file or supported clipboard; renders tree/table/JSON and can extract a claim or compare exp with the current time.

Create a synthetic token.txt fixture for the example. Avoid putting live tokens in shell history or screenshots.

```bash
node index.js --file token.txt --json
```

## Commands and controls

| Control | Behavior in the inspected implementation |
| --- | --- |
| `--file PATH` | Read a token from a file |
| `--clipboard` | Read a supported system clipboard |
| `--claim KEY` | Extract one payload claim |
| `--json` | Emit decoded JSON |
| `--check-expiry` | Compare exp with time without signature verification |

## Interpretation and side effects

Decoding does not verify the signature, issuer, audience or authorization. --check-expiry is only a timestamp check; a successful exit is not evidence that a token is valid or trustworthy.

## Implementation reference

- [package.json](https://github.com/NickCirv/jwt-decode/blob/8564b2ad95580ec5c5b644df786d35e92915453a/package.json)
- [index.js](https://github.com/NickCirv/jwt-decode/blob/8564b2ad95580ec5c5b644df786d35e92915453a/index.js)
- [test/smoke.test.js](https://github.com/NickCirv/jwt-decode/blob/8564b2ad95580ec5c5b644df786d35e92915453a/test/smoke.test.js)
