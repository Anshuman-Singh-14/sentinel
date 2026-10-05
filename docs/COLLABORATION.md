# Working in parallel

Two developers, each with their own Claude Code session, build Sentinel at the
same time. This file is the protocol that keeps their work from clashing.
`CLAUDE.md` points every session here, so a new session follows it without
being told.

## The to-do list is GitHub Issues

**Board:** https://github.com/Anshuman-Singh-14/sentinel/issues

Each issue is one unit of work: a phase, a chore or a fix.

- **The assignee is the lock.** An assigned issue belongs to its assignee. Leave
  it and everything it touches alone, even if it looks stalled. Ask in the issue
  instead.
- **Unassigned and open** means anyone may take it.
- **Phases go in the order in `CLAUDE.md`** (ADR 0009). Only the phase at the
  front is claimable. Chores and fixes can be claimed at any time.
- **New work gets an issue first**, even a small one, so the other side sees it
  before files start changing.

## Starting work

1. `git fetch --prune`, then read the open issues and open PRs:
   `gh issue list` and `gh pr list`. Note which files the open PRs touch:
   `gh pr view N --json files`.
2. **Claim** the issue: `gh issue edit N --add-assignee @me`, then comment with
   the branch name. If someone else got there first, pick something else.
3. Branch from a fresh `main`: `git checkout main && git pull --ff-only`, then
   `git checkout -b <type>/<short-name>`.
4. **Open a draft PR with your first push**: `gh pr create --draft`, with
   `Closes #N` in the body. The draft shows the other side which files you are
   changing while the work is still in progress.

## While working

- **Stay in your lane.** Change only what the issue needs. If you have to edit
  a file that another open PR also edits, say so in both PRs before you do it.
- **Rebase onto `main` at least daily** and always before you mark a PR ready:
  `git fetch && git rebase origin/main`. Small conflicts found early are cheap.
- **Never rewrite someone else's branch.** No force-push except to your own
  branch, and never to `main`.

## Shared files

Almost every change touches the files below. Most conflicts come from them, so
the table gives a rule for each.

| File | Rule |
|---|---|
| `CHANGELOG.md`, `docs/PROGRESS.md` | Edit only in the PR's last commit, after the final rebase. Add your own entry; don't reorder or reword the other side's. On a conflict, keep both. |
| `README.md`, `CLAUDE.md` | Keep edits small and local: a table row or a line in a list. |
| `backend/alembic/versions/` | Before you merge, `alembic heads` must show **one** head. If the other side merged a migration first, rebase and point your `down_revision` at theirs. Never edit a merged migration. |
| `backend/uv.lock`, `frontend/package-lock.json` | Never hand-merge. Take `main`'s version and regenerate (`uv lock` / `npm install`). |
| `docker-compose*.yml`, `.env.example`, `backend/app/config.py` | Add new keys and services; don't reorder or reformat existing ones. |
| `.github/workflows/ci.yml` | Coordinate in the issue first. Renaming a job breaks branch protection (see below). |
| **Numbered IDs:** ADRs (`docs/adr/00NN-*`), threat IDs (`T78`, ...), migration numbers | Reserve the next number in a comment on your issue before you use it. Whoever comments first owns the number. |

## Finishing

1. Rebase onto `main`, run every gate locally (CLAUDE.md, "Test as you go"),
   then update `CHANGELOG.md` and `docs/PROGRESS.md`.
2. Mark the PR ready (`gh pr ready N`) and merge it once CI is green.
3. Merging closes the issue through `Closes #N`, and GitHub deletes the branch.

## What GitHub enforces on `main`

Branch protection applies to everyone, admins included:

- **No direct pushes.** Changes reach `main` only through a PR.
- **CI must pass.** The required checks are the backend, frontend, compose
  smoke test, production smoke test and gitleaks jobs.
- **The branch must be up to date with `main`.** If the other side merged first,
  GitHub blocks the merge until you rebase (or press "Update branch") and CI
  passes again. This is what stops two PRs that each pass alone from breaking
  `main` together.
- No approving review is required, so either developer can merge a green PR on
  their own.

If a CI job is renamed, update the required checks too (repo **Settings →
Branches**), or every merge stays blocked.
