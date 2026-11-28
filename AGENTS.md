# Fetch MCP

A lightweight, SSRF-hardened web fetcher exposing public HTTP(S) content and YouTube transcripts in agent-ready text
formats over an MCP server (`mcp-fetch-server`, supporting `stdio` and Streamable HTTP) and a local CLI (`mcp-fetch`).

What the system must do lives in `REQUIREMENTS.md` and the journeys' acceptance criteria, not here. Don't change
either unilaterally: propose and ask. This file is how we work.

## How we work

Decision-driven development. The domain has a vocabulary of nouns and verbs (`REQUIREMENTS.md` → Terminology), and
every artifact speaks it: requirements, journeys, specs, scenarios and code. Decisions are recorded once, in
`REQUIREMENTS.md`, cited everywhere else, and propagated to everything they touch.

- `/dd-journey` designs a new journey with the user (a design session), says what it must do, and plans its next
  slice.
- **Build** a slice: tests and scenario first, under the conventions below.
- `/dd-review` reviews a branch before it merges: its diff against the criteria, invariants, decisions and specs it
  touches, and its words against Terminology. It proves each bug by running it and proposes fixes, applying them only
  with a yes.
- `/dd-verify` runs a journey and reports where behavior and artifacts disagree, and what's undecided.
- `/dd-decide` records a decision, question or invariant and propagates it everywhere, code included. Given context
  instead (anything from outside that may hold decisions: an edited diagram, a document, an email), it first sorts
  what differs from what's decided.

You propose decisions; the user makes them. When building turns up a rule nobody has decided, don't pick one
silently: use a named placeholder (below), say so, and propose a U#.

## Documents

- `REQUIREMENTS.md`: what is true however the system is used: Terminology, requirements, invariants (I#), the
  Decision Log (D#) and Undecided Questions (U#). One numbering for every journey: a new one takes the next number,
  whichever journey raised it.
- `docs/journeys/<journey>/`: one folder per user journey, each with the same files.
  - `acceptance-criteria.md`: when the journey is done, as Gherkin scenarios in a `gherkin` block per step of the
    journey, each tagged with its criterion's id (`@CO-3`) and the D#s, U#s and I#s it cites. A criterion with several
    cases has a scenario for each, sharing its id.
  - `plan.md`: how the journey is built: the contexts and verbs it uses, the external systems it needs, and its
    slices. A slice is one capability, wired through every part of the system with a scenario that runs it. The first
    is the tracer bullet, the narrowest path a user would recognize; each later one adds one capability. The slices
    still to build are a queue (Next) that grows as running the journey turns up cases.
  - `specs/<nn>-<slice>/spec.md`: one per slice, naming the criteria it covers.
  - `runbook.md`: what needs a person to check (a browser, a real sandbox, a judgment call). Anything that can be
    scripted is a scenario instead.
- `scenarios/<journey>/<nn>-<slice>.txt`: each slice's journey as harness commands and what they print.
- `notes/`: dated working notes, including `/dd-review` and `/dd-verify` reports. They're disposable: delete one once
  its findings are acted on.

Rules for every document:

- **Cite, don't restate.** Criteria, specs and runbooks point at D#, U# and I#; they never copy a rule's wording. A
  changed decision then changes in one place, plus only the artifacts whose meaning changed.
- **Say what's true now; git keeps the history.** No document records what it used to say. A changed decision is
  rewritten to what holds now; a spec is edited to what its capability does now; a dropped spec is deleted. The story
  of a change lives in its commit message, which names the ids it touched (see Commits).
- **Ids never move.** A D#, U# or I# number is never reused or renumbered. A resolved question stays as a one-line
  pointer to its decision, and a withdrawn decision keeps its heading as one line (`### D9. Withdrawn: see D14`), so
  an old reference always leads somewhere.
- **Use the vocabulary.** Documents, code and harness commands use Terminology's words and no others. A new word, or a
  change to one, is a decision.

## Commands

```bash
bun run harness                   # the harness, interactive: type help
bun run harness run <file|folder> # replay scenarios; exits 1 if any prints something else
bun run harness run <…> --write   # accept what they print now
bun test                          # unit, integration, and scenario tests
bun run typecheck                 # tsc --noEmit
bun run lint                      # biome ci .  (bun run lint:fix to fix)
bun run build                     # build dist/index.js and dist/cli.js
bun run verify:replay             # offline 3-form-factor cassette replay (CLI, stdio, Streamable HTTP)
bun run verify:live               # on-demand live-internet verification (add -- --record to refresh cassettes)
```

Run `bun run lint`, `bun run typecheck`, `bun test`, and `bun run harness run scenarios` before calling a change done.

## Commits

Git is where history lives, so a commit that records or propagates a decision says so. Its subject starts with the id
and says what now holds; its body says what it resolves or replaces, and which artifacts it changed:

```text
D12: refunds within 30 days of delivery

Resolves U3. Was: 14 days from purchase. Changes CO-6, CO-7, spec 03-refunds,
scenarios/checkout/03-refunds.txt, src/orders/verbs.ts.
```

`git log --grep D12` is then the whole story of a decision.

## Code conventions

Functional DDD: a pure domain core with all I/O at the edges.

**Layout.** Existing code lives in `src/`. New bounded contexts and mocks follow:

```text
src/
  shared/                 shared kernel: Result, Brand and the ids
  <context>/              one folder per bounded context
  integrations/<system>/  one in-memory mock per external system (and the real client)
cli/                      the harness: session, commands, scenario runner (if enabled)
```

Contexts never import each other; callers (MCP server, CLI, harness) link them. Model only this system's own rules;
an external system's internals are modeled only as far as its mock needs to answer calls.

**Each bounded context has the same files.**

| File | Contents |
|---|---|
| `nouns.ts` | The context's nouns from Terminology, as types. States are discriminated unions, so illegal states can't be represented. |
| `verbs.ts` | The context's verbs from Terminology: one pure function per verb. What was read plus a request in, a `Result` of what to write out (or why not). Every rule about what may change lives here. A verb may call queries. |
| `queries.ts` | The context's derived nouns from Terminology: one pure function each. What was read in, a value out: never a `Result`, never anything to write. How a derived noun is defined lives here. |
| `ports.ts` | The calls the context needs from the outside world, as function types only. No implementations. |

A context that only reads has no `verbs.ts`.

**Verbs change, queries tell.** If the caller writes anything after calling a function, it's a verb; if not, it's a
query. A verb can be refused; a query can't. A verb may call a query, and a query never calls a verb. There are no
`canX` queries: to ask whether something is allowed, call the verb and see whether it's refused. A derived noun is
never stored: no verb writes it, and anything that needs it calls its query.

**Names are the vocabulary.** Types, functions, and commands use Terminology's words. If code needs a word Terminology
doesn't have, propose the term before using it.

**A verb's signature is its contract.** Every exported verb and query declares its parameter and return types explicitly.

**Types.** Model states as discriminated unions. A `switch` over a union ends in `default: return x satisfies never`
(or assigns `x` to `never`), so a new case fails typecheck until it's handled.

**Parse at the edges; don't cast.** Anything from outside (tool arguments, CLI flags, an external system's response)
is parsed into a typed value at the edge, with Zod or a small parser returning `Result`, and code past the edge trusts
the type. No `as` to tell the compiler what a value is, no `!`, no `any`: narrow, parse or restructure instead.

**Errors.** New verbs and ports return `Result` (`ok` / `err`) instead of throwing. Throw only for a programmer error.

## Tests

**Tests first.** Write the failing test, run it to see it fail, then implement. Domain tests are given / when / then
on pure functions and need no mocks.

**Placeholders.** A value or rule that stands in for something undecided is a named constant, commented with the U# it
stands in for, and listed in its slice's spec.
