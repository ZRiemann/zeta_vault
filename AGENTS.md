# zeta_vault Agent Guidance

Before modifying this repository, read and apply the repository-stored ZetaX
rules from `ZRiemann/zsa`:

- `agents/zetax/AGENTS.md`
- `agents/zetax/skills/zetax-project/SKILL.md`
- `agents/zetax/skills/zetax-code-style/SKILL.md`
- `agents/zetax/skills/zetax-cpp-style/SKILL.md`
- `agents/zetax/skills/zetax-python-style/SKILL.md` when Python is touched
- `agents/zetax/skills/zetax-commit/SKILL.md` for commit work

Repository-specific rules:

- Keep the stable public boundary in `include/zeta_vault/zeta_vault.h` as C ABI.
- Keep the C++ wrapper header-only and implemented only in terms of the C ABI.
- Use `zpp/wire` only as the primitive binary codec; keep vault message
  semantics
  in `z::vault::protocol`.
- Do not expose master passwords or decrypted secrets through logs, command-line
  arguments, environment variables, or exception messages.
- Do not implement cryptographic primitives locally.
