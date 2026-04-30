# New Feature Ideas (post-v1 backlog)

Seed file for feature ideas surfaced during the v1 audit passes and
the post-v1 rolling sweeps. Nothing here is committed to a release;
this is a parking lot for things that are **outside** the closure
scope of `V1_RELEASE_AUDIT.md`.

Per the operator's working model: if a sweep pass turns up a good
feature idea, drop a short entry here with enough context to
prioritise it later. Larger designs should graduate into their own
`Tools/<name>/` folder or a dedicated plan file once accepted.

## Conventions

- One idea per entry, scoped tightly enough to estimate in a day or
  less of work. Larger things belong in their own plan document.
- Use the status ladder: `idea` → `accepted` → `in-plan` →
  `landed`. `in-plan` means a dedicated spec / plan file exists.
- Keep the **Why** line grounded in an actual operator pain or
  compliance gap; speculative "might be nice" entries get dropped.
- No roadmap dates. We gate on v1 closure first.

## Template

```markdown
### NFI-<NNN>. <title> [status]

- **Area**: <SIMCARD / SCP11 / ProfilePackage / HilBridge / ...>
- **Why**: <one-line operator or compliance motivation>
- **Sketch**: <3-5 bullet points on shape of the change>
- **Risk**: <what could break, what surface it touches>
- **Exit**: <what "done" looks like, ideally a test + a doc
  update>
```

## Ideas

_None open in the ideas parking lot for this sweep cycle. All active
post-v1 scope currently lives in `V2_ROADMAP.md`:_

- `R2-001` — HSM-backed signer seam for the local SMDPp *(accepted,
  full design in `V2_ROADMAP.md`)*.
- `R2-002` — Cloud KMS provider follow-ups *(accepted, depends on
  R2-001)*.
- `R2-003` — eUICC-side issuer-chain signer coverage *(accepted,
  depends on R2-001)*.

New casual ideas that surface during future passes continue to land
here first; they graduate into `V2_ROADMAP.md` once scoped.

## See also

- `V2_ROADMAP.md` — accepted post-v1 scope, with full designs.
- `V1_FEATURE_PLAN.md` — the **landed** v1 feature plan (F1-F4).
- `V1_RELEASE_AUDIT.md` — the audit log driving v1 closure.
- `guides/CAPABILITIES.md` — current, released capability surface.
