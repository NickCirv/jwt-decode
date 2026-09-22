# jwt-decode — research record

## Revision and scope

- Repository: [NickCirv/jwt-decode](https://github.com/NickCirv/jwt-decode)
- Commit: `8564b2ad95580ec5c5b644df786d35e92915453a`
- Tree: `d530d5c2883605a4fef9ec642467000e69e34004`
- Captured: 6 of 6 eligible text files (all eligible text files).
- Recursive tree truncated: `False`.
- Runtime verification: **unverified**; no repository code, installation or test command was executed.

The captured file inventory is broader than the semantic review. Authoring inspected package metadata, entrypoint/argument handling and implementation paths relevant to the claims below, plus test declarations. This is documentation research, not a line-by-line security audit. Generated/binary artifacts, lockfiles and file types outside the acquisition filter were not inspected.

## Claim and evidence

| Claim | Pinned evidence | Status |
| --- | --- | --- |
| Runtime requirement and executable mapping | [package.json](https://github.com/NickCirv/jwt-decode/blob/8564b2ad95580ec5c5b644df786d35e92915453a/package.json) | verified in manifest; installation unverified |
| Inspect the encoded header and payload of a JWT locally. | [implementation](https://github.com/NickCirv/jwt-decode/blob/8564b2ad95580ec5c5b644df786d35e92915453a/index.js) | partially verified by static implementation review |
| Operational limits and side effects | [implementation](https://github.com/NickCirv/jwt-decode/blob/8564b2ad95580ec5c5b644df786d35e92915453a/index.js) and source map in [reference](REFERENCE.md) | partially verified; runtime unverified |
| Test command definition | [package.json](https://github.com/NickCirv/jwt-decode/blob/8564b2ad95580ec5c5b644df786d35e92915453a/package.json) | verified as a declaration only |

## Findings carried into the rewrite

Decoding does not verify the signature, issuer, audience or authorization. --check-expiry is only a timestamp check; a successful exit is not evidence that a token is valid or trustworthy.

No runtime checks were executed for this documentation review. The committed smoke test checks entrypoint JavaScript syntax; it does not exercise the command behavior.

## Documentation inventory and disposition

| Existing document | Disposition |
| --- | --- |
| [README.md](https://github.com/NickCirv/jwt-decode/blob/8564b2ad95580ec5c5b644df786d35e92915453a/README.md) | Rewritten overview; historical copy remains at this pinned URL. |

New supporting documents: `docs/REFERENCE.md` and `docs/RESEARCH.md`. No original source or protected legal/security file was changed.

## Protected-file evidence

- `LICENSE` SHA-256 `68729cab364d82364078b08d8580ccfa51dc69c81a7d64e8d8d47a1da6c9349d`.

## Remaining verification

Clean installation, useful-command execution, malformed input, side-effect boundaries, platform compatibility and end-to-end tests remain unverified. Package-registry availability and live API destinations were not checked. No performance, customer-adoption, compliance or production-readiness claim is made.

## Captured evidence index

- [LICENSE](https://github.com/NickCirv/jwt-decode/blob/8564b2ad95580ec5c5b644df786d35e92915453a/LICENSE) · blob `05b804beeec7d1a6c933d087387ba4adf6463d93`.
- [README.md](https://github.com/NickCirv/jwt-decode/blob/8564b2ad95580ec5c5b644df786d35e92915453a/README.md) · blob `49b098578e3f9ac71d42feb1fe4bf03021346fa4`.
- [package.json](https://github.com/NickCirv/jwt-decode/blob/8564b2ad95580ec5c5b644df786d35e92915453a/package.json) · blob `6d4725f98fc88677702775d0f56f0a9cbfd18eba`.
- [.github/workflows/ci.yml](https://github.com/NickCirv/jwt-decode/blob/8564b2ad95580ec5c5b644df786d35e92915453a/.github/workflows/ci.yml) · blob `44515034a394670de44454a7a1bd2c7ef0c9836e`.
- [index.js](https://github.com/NickCirv/jwt-decode/blob/8564b2ad95580ec5c5b644df786d35e92915453a/index.js) · blob `1c8f9c30ab72f79376e662f6de532dcddb899360`.
- [test/smoke.test.js](https://github.com/NickCirv/jwt-decode/blob/8564b2ad95580ec5c5b644df786d35e92915453a/test/smoke.test.js) · blob `a2eba067c997f85dfb0e2dbaf147bbde33266e19`.

## Tree files outside the captured text set

These paths were mapped but their contents were not acquired in this research pass:

- `banner.svg`
