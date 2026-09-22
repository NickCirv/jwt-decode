![jwt-decode — Nicholas Ashkar repository collection](assets/nicholas-ashkar/banner.png)

# jwt-decode

Inspect the encoded header and payload of a JWT locally.


<a id="usage"></a>

## What it does

Reads a token argument, stdin, file or supported clipboard; renders tree/table/JSON and can extract a claim or compare exp with the current time. See the pinned [implementation](https://github.com/NickCirv/jwt-decode/blob/8564b2ad95580ec5c5b644df786d35e92915453a/index.js).


<a id="install"></a>

## Quickstart

Node requirement from the inspected manifest: **`>=20`**. Create a synthetic token.txt fixture for the example. Avoid putting live tokens in shell history or screenshots.

The following example is **source-inspected, not executed**. It uses a pinned checkout; npm package publication is not assumed. Replace project paths or provide the stated input fixtures before running it.

```bash
git clone https://github.com/NickCirv/jwt-decode.git
cd jwt-decode
git checkout 8564b2ad95580ec5c5b644df786d35e92915453a
npm install --ignore-scripts
node index.js --file token.txt --json
```

Dependencies are installed with lifecycle scripts disabled in this recipe. Read the package scripts before enabling any lifecycle step required by your environment.

## Usage and reference

`jwt-decode` | `jwtd` are the executable names declared by the package. [Command reference](docs/REFERENCE.md) covers source-backed options and entry points.

| Control | Behavior in the inspected implementation |
| --- | --- |
| `--file PATH` | Read a token from a file |
| `--clipboard` | Read a supported system clipboard |
| `--claim KEY` | Extract one payload claim |
| `--json` | Emit decoded JSON |
| `--check-expiry` | Compare exp with time without signature verification |

## Limits and operational notes

Decoding does not verify the signature, issuer, audience or authorization. --check-expiry is only a timestamp check; a successful exit is not evidence that a token is valid or trustworthy.

## Development

No runtime checks were executed for this documentation review. The committed smoke test checks entrypoint JavaScript syntax; it does not exercise the command behavior.

| Script | Declared command |
| --- | --- |
| `test` | `node --test` |

Work from the pinned source, keep changes focused, and reproduce the affected behavior with a small fixture before proposing a change. Existing contribution and security policies remain authoritative where present.

## Research and status

[Research record](docs/RESEARCH.md) identifies the inspected revision, source evidence, documentation disposition and verification gaps. Static inspection supports the descriptions here; runtime behavior, dependency installation and current hosted services remain unverified.

## License and author

[License](https://github.com/NickCirv/jwt-decode/blob/8564b2ad95580ec5c5b644df786d35e92915453a/LICENSE)

[Nicholas Ashkar](https://nicholashkar.com) · Applied AI, systems and consulting.
