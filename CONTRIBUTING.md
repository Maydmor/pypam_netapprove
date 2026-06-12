# Contributing to pam-netapprove

Thanks for your interest! This project sits on the `sudo` authentication path and
runs as root, so we hold contributions to a high bar — but that also means there's a
lot of value in careful tests, docs, and review. All experience levels welcome.

## Ways to help

- **Bug reports** — especially anything where the module could fail *open* (return
  `PAM_SUCCESS` when it shouldn't) or downgrade unexpectedly.
- **Tests** — more property/edge-case coverage on the crypto core, replay, and the
  three-return-code logic.
- **A phone app (Phase 4)** — the big missing piece. It must generate its key in the
  secure enclave / StrongBox / Android Keystore, gate signing on a biometric, and
  reimplement the canonical byte encoding from `netapprove_core/challenge.py` exactly.
- **Docs** — deployment notes for distros beyond Ubuntu, operational runbooks.

## Getting set up

```bash
python -m venv .venv && source .venv/bin/activate    # Windows: .\.venv\Scripts\activate
pip install -e ".[relay,client,dev]"
pytest -q                                            # all green before you start
```

## Workflow

1. **Open an issue first** for anything non-trivial, so we can agree on the approach.
2. Branch from `main`; keep each PR focused on one change.
3. Add tests. A PR that changes behavior without a test won't be merged.
4. Run the full suite (`pytest -q`) and, for network changes, the live smoke test
   (`python scripts/smoke_phase3.py`).
5. Write a clear PR description. For auth-path or wire-format changes, explain the
   security reasoning and cite the relevant section of the brief in `docs/`.

## Code style

The codebase follows a deliberate early-exit style:

- **Validate inputs and load variables first; exit early on anything wrong.** Logic
  runs only once everything is known good.
- **Fail closed.** On the auth path, any unexpected error resolves to
  `PAM_AUTH_ERR` — never a silent success. No bare `except: pass`.
- **Flat control flow.** Invert conditions and `return`/`continue` early instead of
  nesting the happy path.
- **Typed returns, not naked dicts.** Use dataclasses for multi-field results.
- **Keep `netapprove_core` pure.** No PAM, no network imports in the security core —
  it must stay independently auditable and reusable (e.g. by a future Rust port).

## The wire contract

`netapprove_core/challenge.py::Challenge.to_canonical_bytes` defines the exact bytes
that get signed. It is a contract shared with every signer (the phone app).

- Do **not** change the layout casually. If you must, bump `CHALLENGE_MAGIC`
  (`NAPCHAL1` → `NAPCHAL2`) and update all signers in the same release.
- Any change needs the §7 tests to still pass: deterministic, MAGIC-prefixed,
  injective across field boundaries, and every field provably bound to the output.

## Security issues

Do **not** file public issues for vulnerabilities. Email the maintainers privately
(replace with the project's security contact, e.g. `security@<project-domain>`), give
a clear description and, if possible, a reproducer, and allow reasonable time for a
fix before public disclosure. We'll credit you unless you'd prefer otherwise.

## License

By contributing, you agree your contributions are licensed under the project's
[MIT License](LICENSE).
