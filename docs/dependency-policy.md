# Dependency policy

Dependencies increase QuicSync's security, maintenance, binary size, and
licensing obligations. Add one only when the benefit is greater than
implementing or maintaining the required functionality locally.

## Adding or changing a dependency

A pull request that adds a dependency or enables a new feature must document:

- the capability it provides and alternatives considered;
- whether it is a runtime, build, or development dependency;
- the exact Cargo features enabled and why each is needed;
- its direct license and any notable transitive license impact;
- security and maintenance signals, including recent releases and known
  advisories; and
- expected effects on supported targets, binary size, and compile time when
  material.

Disable default features when they are unnecessary. Prefer a workspace-level
version and feature declaration when multiple crates use the same dependency.
Commit `Cargo.lock` for reproducible application builds, and do not edit it by
hand.

## License rules

MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC, and Zlib dependencies are
generally acceptable after review. MPL-2.0 and other weak-copyleft licenses
require explicit maintainer review of their distribution obligations. GPL, AGPL,
SSPL, non-commercial, source-available, custom, or unknown licenses require
maintainer approval before merge and must not be added merely because they are
transitively selected.

License expressions and notices must be preserved. A crate with multiple offered
licenses may be used only under terms compatible with this repository's MIT
distribution. The pull request must call out ambiguity rather than assuming
compatibility.

## Security and maintenance

- Run `cargo audit` for known RustSec advisories when dependency metadata
  exists.
- Review duplicate or unmaintained crates reported by dependency tooling.
- Use the minimum supported version that is actively maintained; avoid exact
  pins unless reproducibility or a documented upstream issue requires one.
- Do not merge a dependency with a known exploitable advisory unless the pull
  request documents why QuicSync is unaffected or includes a time-bounded
  exception approved by the owner.
- Remove unused dependencies and features promptly.

Automated update pull requests receive the same tests, license review, ownership
review, and merge requirements as other changes. Major-version updates require
release-note and migration review; security updates should be prioritized
according to impact.
