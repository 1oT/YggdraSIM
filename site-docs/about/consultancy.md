---
title: Consultancy, custom features, and contact
description: Engage 1oT OÜ for custom secure-element tooling, eUICC / eSIM integration, HIL setup, and consultancy around YggdraSIM.
tags:
  - about
  - consultancy
  - commercial
  - contact
---
<!--
SPDX-License-Identifier: GPL-3.0-or-later
Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
-->


# Consultancy, custom features, and contact

YggdraSIM is open source under `GPL-3.0-or-later`. The engineering
behind it is delivered by **1oT OÜ**, an independent global IoT
connectivity provider based in Tallinn, Estonia. Teams that need to
move faster than the public toolkit on its own can engage the 1oT
team directly for tailored work.

## What 1oT can help with

- **eUICC / eSIM integration** — SGP.22 and SGP.32 bring-up, device-side
  LPAd and IPAd, eIM remote management, and ES9+ interop
- **SAIP profile work** — profile audits, linting, transcoding,
  operator-specific binders, `3GPP-USIM` and `GSM-ACCESS` templates
- **SCP11 relay debugging** — live ES9+ flows, PK/SK negotiation,
  MetaData signing, and eSIM bound-profile download troubleshooting
- **HIL rigs** — SIMtrace2 cardem, passive sniffing, APDU capture,
  pcap replay, and protocol-conformance harnesses around
  `ETSI TS 102 221` and GlobalPlatform
- **SCP80 OTA** — campaign design, PoR handling, crypto review, and
  production-grade key management
- **Private forks** — a named feature branch where commercial work
  is performed, with back-porting to YggdraSIM main where it does not
  conflict with customer confidentiality
- **Training** — focused sessions on the secure-element stack for
  your engineering team (APDU, GlobalPlatform, SGP.22/32, SAIP)

## Engagement shapes

| Shape | Best for | Deliverable |
| --- | --- | --- |
| **Scoped consultancy** | Fixed questions, technical reviews, architecture sign-off | Written report + review call |
| **Custom feature** | A concrete missing capability in YggdraSIM | Named feature branch + merge |
| **Retainer** | Ongoing SIM / eSIM work across a product lifecycle | Dedicated hours per month |
| **Integration audit** | Existing in-house SIM / eSIM pipeline | Gap analysis + remediation plan |

## Working model

1. **Intro call.** A 30-minute scoping conversation to understand the
   target standards, the card stack, and the commercial envelope.
2. **Proposal.** A written scope with acceptance criteria, a delivery
   plan referencing the relevant YggdraSIM subsystems, and a fixed
   price or a capped time-and-material rate.
3. **Execution.** Work lands on a named branch in either the public
   YggdraSIM repository or a private mirror, depending on the
   engagement. Progress is tracked against the acceptance criteria.
4. **Handover.** Deliverables ship with runbooks that live in
   `site-docs/how-to/` or an equivalent internal doc tree, so the
   same documentation surface powers both the code and its operation.

## Contact

- **Commercial conversations** — reach out via the contact form on
  [1ot.com](https://www.1ot.com/) or through the inbound channel your
  1oT account manager has provided.
- **Public bugs and feature requests** — open a GitHub issue at
  [`1oT/YggdraSIM`](https://github.com/1oT/YggdraSIM/issues).
- **Security disclosures** — follow the process in
  [`.github/SECURITY.md`](https://github.com/1oT/YggdraSIM/blob/main/.github/SECURITY.md)
  rather than opening a public issue.

Consultancy engagements are covered by a separate commercial
agreement between 1oT OÜ and the customer. The public YggdraSIM
license (`GPL-3.0-or-later`) continues to govern the open source code
itself, including any changes that are merged back to the public
repository.

## Related pages

- [About YggdraSIM](index.md)
- [Authors & Attribution](authors.md)
- [License (GPL-3.0-or-later)](license.md)
- [NOTICE (Attribution & Third-Party)](notice.md)
- [Contributing](contributing.md)
