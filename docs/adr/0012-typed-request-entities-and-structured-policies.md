# ADR 0012: Typed request entities and structured Cedar policies

| Field | Value |
|---|---|
| Status | Accepted |
| Date | 2026-10-18 |
| Deciders | Justus Perillieux |
| Supersedes | — |
| Related | PRD-0001, ADR-0002, ADR-0004, ADR-0009 |

## Context

`authorization.Request` names its principal, action and resource with one
shared type, `authorization.Entity{Type, ID}`. The compiler cannot tell
the three apart, so swapping two of them in a struct literal or in a helper
(`principalEntity(...)` returning an `Entity` that ends up as the resource)
compiles and fails only at evaluation time, usually as a silent deny.

Policies, on the other hand, are only accepted as Cedar text from an
`authorization.PolicySource`. The simplest and most common policies, a
`permit` or `forbid` whose scope pins the principal, action and resource to
single entities, are written as string literals such as
`permit(principal == User::"alice", action == Action::"read", resource);`.
The entities in that text are the same values a `Request` carries, but
nothing connects the two, and building such text from variables invites
quoting mistakes and policy injection through entity IDs.

## Decision drivers

- D1: Mixing up principal, action and resource must be a compile error.
- D2: Simple policies should be expressible with the same Go values a
  request uses, without string building.
- D3: Building a policy from untrusted values (for example a user ID) must
  not allow injecting policy text.
- D4: Full Cedar (conditions, `in`, `is`, templates) stays available as text.
- D5: `authorization` stays independent of cedar-go (ADR-0002, ADR-0003).
- D6: A structured policy always states which kind of resource it governs,
  so a policy cannot silently apply to every resource type in the schema.

## Considered options

1. **Distinct `Principal`, `Action` and `Resource` structs in
   `authorization`; a structured `Policy` and a `Policies` source in
   `authorization/cedar` (chosen)**
   - Pro: D1 by construction; one `Principal` value builds both the request
     and the policy scope (D2); the `cedar` package renders text with
     cedar-go's AST builder after validating every entity, so IDs are always
     quoted and escaped (D3); text sources keep working (D4); cedar-go stays
     out of `authorization` (D5).
   - Con: breaks every caller that builds `Request` from `Entity` values.
2. **Keep `Entity`; add only the structured policy**
   - Pro: no breaking change.
   - Con: does not address D1; the policy struct would repeat the same
     ambiguity.
3. **Generic `Entity[K]` with marker kinds**
   - Pro: one definition, still distinct types.
   - Con: generics in the contract types (ADR-0002 keeps the API free of
     them); `Entity[principalKind]{...}` reads worse than
     `Principal{...}` at every call site.
4. **Expose cedar-go's AST (`ast.Permit().PrincipalEq(...)`) in examples**
   - Pro: no new API; full Cedar expressiveness.
   - Con: leaks cedar-go types into callers' code; unrelated to the
     request types, so D1 and D2 are not met.

## Decision

We will replace `authorization.Entity` with three structs and type the
fields of `authorization.Request` with them:

- `authorization.Principal{Type, ID}`;
- `authorization.Action{ID}`: the Cedar entity type of an action is always
  `Action`, so callers name only the action (`Action{ID: "read"}` is
  `Action::"read"`); namespaced action types are not supported;
- `authorization.Resource{Type, ID}`.

We will add to `authorization/cedar`:

- `Effect` with `Permit` and `Forbid`;
- `Policy{Effect, Principal, Action, Resource}`. `Principal` and `Action`
  are pointers: nil matches any principal or action, a value matches exactly
  that entity (`==`). `Resource` is a required value whose `Type` must be
  set (D6): with an `ID` it matches exactly that resource (`==`), without
  one every resource of that type (`is`);
- `Policies []Policy`, an `authorization.PolicySource` that validates every
  policy with the same identifier rules the engine applies to requests and
  renders them through cedar-go's AST into Cedar text. An empty list, an
  unknown effect, a missing resource type or an invalid entity is reported
  as
  `authorization.ErrInvalidSource`; the engine then fails closed with
  `authorization.ErrSource` as for any failing source (ADR-0004).

Anything beyond these scopes (conditions, `in`, templates) keeps using Cedar text through any other
`PolicySource`. This amends the `authorization` and `authorization/cedar`
rows of the public API table in ADR-0009.

## Consequences

### Positive
- Request and policy share one vocabulary; a principal can no longer be
  passed where a resource is expected.
- Simple policies need no Cedar syntax and are safe to build from
  untrusted IDs.

### Negative
- Breaking change for every caller constructing `authorization.Request` or
  using `authorization.Entity`; released as `v0.2.0` and listed in the
  changelog.
- Actions can no longer use a namespaced entity type such as
  `App::Action`.
- Structured policies cover only `==` and resource-type scopes; users mix
  them with text
  sources by writing their own `PolicySource` that concatenates both.

### Follow-ups
- Add `in` scopes or conditions to `Policy` only when a user needs
  them, through a new ADR.

## Links

- `authorization/types.go`, `authorization/cedar/policy.go`
- `TestPoliciesRenderStructuredScopes`, `TestPoliciesRejectInvalidPolicies`,
  `TestEngineEvaluatesStructuredPolicies`
