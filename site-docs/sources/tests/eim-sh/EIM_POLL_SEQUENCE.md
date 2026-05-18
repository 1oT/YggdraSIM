# eIM poll command sequence (current)

This describes exactly what we send to the eIM server and how we interpret the response. Use it to compare against SGP.32 / vendor docs when debugging "no packages" (result code 127).

---

## 1. Prerequisites (before poll)

- **Card:** ISD-R selected; we have read EID (BCD string) and eIM config from the card.
- **eIM base URL:** From card’s GetEimConfigurationData (e.g. `eim1.example.test`) or config `EIM_BASE_URL`. Normalized to `https://<fqdn>`.
- **Path:** Config `EIM_HTTP_PATH` = `/gsma/rsp2/asn1` (default).
- **Protocol:** Config `EIM_HTTP_PROTOCOL` = `gsma/rsp/v2.1.0` (default).

We do **not** send euiccChallenge, eimId, or other JSON fields in this flow; the first request is binary only (GetEimPackage TLV).

---

## 2. Request we send (first poll, no prior ack)

**HTTP**

- **Method:** POST  
- **URL:** `https://<eim_fqdn>/gsma/rsp2/asn1`  
  Example: `https://eim1.example.test/gsma/rsp2/asn1`  
- **Headers:**
  - `Content-Type: application/x-gsma-rsp-asn1`
  - `Accept: application/json, application/x-gsma-rsp-asn1`
  - `X-Admin-Protocol: gsma/rsp/v2.1.0` (if `EIM_HTTP_PROTOCOL` non-empty)

**Body (binary BER-TLV)**

- Single TLV: **GetEimPackage** (tag `BF 4F`) containing **EID** (tag `5A`).
- Build:
  - EID from card is a BCD digit string (e.g. `89045967676472615349763031303005`).
  - Encoded to bytes: two digits per byte, high nibble first → 16 bytes for a 32-digit EID.
  - Inner TLV: `5A` + length (1 byte) + EID bytes → e.g. `5A 10 <16 bytes>`.
  - Outer TLV: `BF 4F` + length (1 byte) + inner TLV.
- Example (EID 16 bytes): request body hex starts with `BF 4F 12 5A 10` followed by 16 EID bytes (total 22 bytes).

GetEimPackageRequest (tag BF4F) ASN.1:
- **eidValue** [APPLICATION 26] Octet16 — tag **5A** (we send this).
- **notifyStateChange** [0] NULL OPTIONAL — notify eIM to update eUICC info (e.g. profiles).
- **stateChangeCause** [1] StateChangeCause OPTIONAL.
- **rPLMN** [2] OCTET STRING (SIZE(3)) OPTIONAL — MCC+MNC of last registered PLMN (3GPP TS 24.008).

We currently send **only** EID (5A); we do **not** send notifyStateChange [0], stateChangeCause [1], or rPLMN [2]. Sending only EID may be why the eIM returns **undefinedError(127)** instead of noEimPackageAvailable(1).

---

## 3. Response we receive (current behaviour)

**Observed:** 6 bytes, hex `BF 4F 03 02 01 7F`.

**Parsed as:**

- Tag: `BF 4F` (GetEimPackageResponse CHOICE).
- Length: `03`.
- Value: `02 01 7F` → DER INTEGER **127** = **eimPackageError ::= undefinedError(127)**.

So we are **not** getting `noEimPackageAvailable(1)` (no package); we are getting **undefinedError(127)** (generic error). The eIM is indicating an error condition, not “no packages available”.

GetEimPackageResponse CHOICE (tag BF4F):
- euiccPackageRequest [81] (BF51), ipaEuiccDataRequest [82] (BF52), profileDownloadTriggerRequest [84] (BF54), or
- **eimPackageError** INTEGER { noEimPackageAvailable(1), eidNotFound(2), invalidEid(3), missingEid(4), **undefinedError(127)** }

We treat 127 as polling complete (no packages to ack) and do not send a follow-up. The root cause of the undefinedError may be the request (e.g. missing optional fields) or server state.

---

## 4. How we read the response (binary path)

- If body does not start with `{`, we treat it as binary.
- We parse BER-TLV:
  - GetEimPackageResponse (BF4F) value INTEGER 127 → eimPackageError undefinedError(127); we set `pollingComplete = True`, no packages.
  - Tag `04` (OCTET STRING) → treat value as one package (base64-encode and append to `euiccPackageList`).
  - Tag `0C` (IA5String) and value looks like base64 → append to package list.
  - Any constructed tag (e.g. `30`, `31`, `A0`–`A4`, `81`–`84`, `BF`) → recurse into value and merge out `euiccPackageList`, `transactionId`, `pollingComplete`.
- So for `BF 4F 03 02 01 7F`: we see tag `BF` (first byte), then multi-byte tag so full tag is `BF 4F`, length 3, value `02 01 7F`. We do **not** treat `0F` as result code (we only treat tag byte `0x0F` for that). We recurse into `BF 4F`’s value; inside there is no TLV we collect as packages, and we don’t have a special case for “inner value = INTEGER 127”. So we end up with **packages = []** and default **pollingComplete = True**. (If the server sent a different structure with an explicit result code tag, we’d still need to map 127 → no packages / complete.)

So for the **exact** 6-byte response:

- **Scenario 2 (reading):** We are reading the response correctly: one TLV, value = INTEGER 127. We currently do not set pollingComplete from inside BF4F; we just don’t find any OCTET STRING packages, so package list stays empty. So “no packages” is correct; the only nuance is whether 127 should explicitly set pollingComplete when it’s inside BF4F (we could add that for clarity).

---

## 5. Continuation poll (when we *do* have packages)

If the server had returned packages:

- We would relay them to the card (StoreData), get a card result (euiccPackageResult).
- Next request would be **JSON** (we set `raw_body = None`): same URL and headers, but body = JSON with at least `euiccPackageResult` (base64) and the other eIM fields (eimFqdn, eimId, eid, etc.) so the server can match the session and record the ack.

So the **first** request is binary (GetEimPackage with EID only); **subsequent** requests (if any) are JSON with euiccPackageResult.

---

## 6. Summary table

| Step | What we send | What we get (current) |
|------|----------------|----------------------|
| 1    | POST … body = GetEimPackage (BF4F) with EID (5A) only | 6 bytes: `BF 4F 03 02 01 7F` → **eimPackageError undefinedError(127)** (generic error, not noEimPackageAvailable(1)) |
| 2    | (Only if step 1 returned packages) JSON POST with euiccPackageResult + other fields | — |

---

## 7. eimPackageError: 1 vs 127

GetEimPackageResponse eimPackageError INTEGER:
- **noEimPackageAvailable(1)** — no package for this eUICC.
- eidNotFound(2), invalidEid(3), missingEid(4).
- **undefinedError(127)** — generic/undefined error.

We receive **127 (undefinedError)**, not 1 (noEimPackageAvailable). So the eIM is returning a **generic error**, not “no package”. A different server may log NO_EIM_PACKAGE_AVAILABLE (1); our eIM returns 127 on the wire.

We parse and log the error by name (e.g. `eimPackageError=undefinedError(127)`). Next step: try adding optional GetEimPackageRequest fields (notifyStateChange [0], stateChangeCause [1], rPLMN [2]) to see if the eIM then returns 1 instead of 127.

---

## 8. Clearing a stuck transaction ("clear ack")

If the **first** request left the eIM in a state where it keeps returning "no package" until the transaction is closed, we may need to **acknowledge even when we got zero packages** so the server can clear the session.

- **Current behaviour:** When we get `pollingComplete` and **no** packages we do **not** send a follow-up; we just return.
- **Optional behaviour:** With `EIM_CLEAR_ACK_ON_NO_PACKAGE=true`, when we get no packages we send one JSON POST with the same eIM fields and `euiccPackageResult=""` to signal "no packages received, transaction complete." The server may require this so the next GetEimPackage is not treated as a continuation of a hung transaction.

Config: `EIM_CLEAR_ACK_ON_NO_PACKAGE` (default false). When true and we get no packages, we send **ProvideEimPackageResult** (BF50) with **eimPackageResultResponseError [0]** and **eimPackageResultErrorCode** undefinedError(127), so the eIM can close the transaction. See `EIM_ESIPA_ASN1_REFERENCE.md` for ESIPA message set.

Optional: `EIM_CLEAR_ACK_GENERIC_ERROR_HEX` — custom hex TLV for the result (e.g. a different error code). If unset, we use the standard ProvideEimPackageResult error TLV (BF50078005300302017F). If the server returned a `transactionId`, it is included in the clear-ack request.

---

## 9. Scenarios vs this sequence

1. **eIM does not hand over packages**  
   Server could require something we don’t send (e.g. euiccChallenge, eimId, or registration). Our **first request contains only EID** inside GetEimPackage; no challenge, no eimId in the binary body. So it’s possible the server expects more in the request (or a different first step) before it will return packages.

2. **We are not reading the response correctly**  
   For the 6-byte response we do read it: one TLV, value = INTEGER 127. We don’t extract any packages because there are no OCTET STRINGs. We could add an explicit rule: “if GetEimPackageResponse (BF4F) value is INTEGER 127 (or 0), treat as no packages and polling complete.”

3. **We are not requesting correctly**  
   If the server required a different or larger request, it would often respond with an HTTP error or a different result code. A clean **127** suggests the server understood the request and is explicitly saying “no package.” The eIM may require optional GetEimPackageRequest fields (notifyStateChange [0], stateChangeCause [1], rPLMN [2]) so it returns 1 or a success branch instead of 127.

---

4. **Transaction left open**  
   The first poll might put the server in a state where it keeps returning 127 until we send an explicit "no packages" ack (see §8). Use `EIM_CLEAR_ACK_ON_NO_PACKAGE` to test.

---

## 10. References

- **ESIPA ASN.1:** `tests/eim-sh/EIM_ESIPA_ASN1_REFERENCE.md` — EsipaMessageFromIpaToEim / FromEimToIpa, GetEimPackageRequest/Response, ProvideEimPackageResult (BF50), EimPackageResult, EimPackageResultResponseError.
- Request body build: `SCP11/orchestrator.py` → `_build_get_eim_package_tlv(eid)` (BF4F), `_build_provide_eim_package_result_error_tlv(127)` (BF50 clear-ack).
- HTTP call: `SCP11/es9_client.py` → `poll_eim()` → `_post_eim_binary()` or JSON.
- Response parse: `_parse_eim_binary_response(raw)` (eimPackageError, packages, pollingComplete).
