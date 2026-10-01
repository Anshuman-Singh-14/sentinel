# Claude Code kickoff prompts

Setup: put `CLAUDE.md` in the repo root and the `docs/` folder beside it, open the folder in VS Code, and start Claude Code. Switch to **Plan Mode** (Shift+Tab) for the planning step of each phase.

---

## 1. First message (paste this)

```
Read CLAUDE.md and every file in docs/spec/ carefully.

Before writing any code:
1. Summarize Sentinel's architecture back to me in under 15 bullet points so I can confirm you understood it.
2. List any gaps, contradictions, or risky assumptions you see in the specs (security, feasibility inside Docker, scope creep for a capstone), with a suggested resolution for each.
3. Propose the plan for Phase 0 only: files to create, dependencies with pinned versions and one-line justifications, and the commands I'll use to verify it.

Do not start implementing until I reply "approved".
```

## 2. Start of each subsequent phase

```
We are starting Phase <N> — <name>. Phase <N-1> is complete per docs/PROGRESS.md.

Re-read CLAUDE.md, docs/spec/05-phases.md (Phase <N>) and any spec sections it depends on.
Give me the plan: files to add/change, new dependencies, key design decisions, how each acceptance criterion will be tested, and any security concerns.
Wait for "approved" before writing code.
```

## 3. After approval

```
Approved. Implement Phase <N> in small commits. After each logical step run the relevant tests and linters and fix failures before moving on.
When finished, give me the phase report defined in CLAUDE.md, update docs/PROGRESS.md, and stop.
```

## 4. Useful follow-ups

- `Review the code from this phase as a hostile security auditor. List concrete issues with file/line references, then fix the high and medium ones.`
- `Explain the design decisions in this phase as if I'm defending them to my capstone panel. Write an ADR in docs/adr/ for the most important one.`
- `Update docs/threat-model.md for what we added this phase.`
- `Run the full test suite and security checks and report anything failing.`
