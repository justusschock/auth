# ADR 0001: Record architecture decisions

| Field | Value |
|---|---|
| Status | Accepted |
| Date | 2026-10-18 |
| Deciders | Justus Perillieux |
| Supersedes | — |
| Related | PRD-0001 |

## Context

Recorded retrospectively for the first public release. go-auth grew as a set
of security-sensitive packages whose design rationale (why a check exists, why
a value is hashed, why a test pins exact errors) lived in commit messages and
review threads. Public contributors, human or agent, need that rationale in
the repository, next to the code, before they change it.

## Decision drivers

- D1: Contributors must be able to find why a security check exists before
  removing or relaxing it.
- D2: Decisions must be reviewable in the same pull request as the code.
- D3: History must stay intact; a reversed decision should still be readable.
- D4: Low ceremony: Markdown in the repository, no external tooling.

## Considered options

1. **MADR-style ADRs in `docs/adr/`, plus PRDs in `docs/prd/`, docs first**
   - Pro: versioned with the code, reviewed in pull requests, readable on
     GitHub; PRDs give requirement IDs that tests can cite.
   - Con: discipline needed to write them before or with the code.
2. **Design notes in the wiki or issue tracker**
   - Pro: easy to edit.
   - Con: not versioned with the code, easy to drift, not reviewed with
     changes.
3. **Commit messages and code comments only**
   - Pro: no extra files.
   - Con: rationale scattered and hard to find; no index; no requirement IDs.

## Decision

We will record requirements as PRDs (`docs/prd/NNNN-title.md`) and decisions
as MADR-style ADRs (`docs/adr/NNNN-title.md`), using the templates in those
directories, and work docs first:

- A new or changed behaviour is described in a PRD and, where a design choice
  is involved, an ADR before or in the same pull request as the code (as
  earlier commits).
- New documents start as `Proposed` and become `Accepted` when merged.
- Accepted ADRs are immutable except for their status line. A changed
  decision is a new ADR with `Supersedes: ADR-NNNN`; the old one becomes
  `Superseded by ADR-MMMM`.
- [docs/README.md](../README.md) indexes every PRD and ADR with its status
  and is updated with every addition or status change.
- Requirement IDs (`FR-AUTH-NN`, `NFR-AUTH-NN`) are never reused, and tests
  cite them in comments.

## Consequences

### Positive
- The security model and its trade-offs are discoverable and reviewable.
- Requirement IDs make test coverage of each requirement traceable.

### Negative
- Every significant change carries documentation work.
- The first ADRs are retrospective: they describe the code as built and argue
  from its evident trade-offs rather than from recorded discussions.

### Follow-ups
- Keep [AGENTS.md](../../AGENTS.md) and the index in sync with this process.

## Links

- MADR: https://adr.github.io/madr/
