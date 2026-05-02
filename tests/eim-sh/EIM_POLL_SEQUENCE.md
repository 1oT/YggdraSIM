# eIM poll command sequence

This describes the request/response flow used to poll an eIM server, and how
the simulator interprets the response. Use it to compare against
SGP.32 / vendor docs when debugging "no packages" (result code 127).

---

## 1. Prerequisites (before poll)

- **Card:** ISD-R selected; the EID (BCD string) and eIM config have been read from the card.
- **eIM base URL:** From the card's `GetEimConfigurationData` (e.g. `eim.example.test`) or config `EIM_BASE_URL`. Normalised to `https://<fqdn>`.
- **Path:** Config `EIM_HTTP_PATH` = `/gsma/rsp2/asn1` (default).
- **Protocol:** Config `EIM_HTTP_PROTOCOL` = `gsma/rsp/v2.1.0` (default).

The simulator does **not** send `euiccChallenge`, `eimId`, or other JSON fields in this flow; the first request is binary only (`GetEimPackage` TLV).

---

## 2. Outgoing request (first poll, no prior ack)

**HTTP**

- **Method:** POST
- **URL:** `https://<eim_fqdn>/gsma/rsp2/asn1`
  Example: `https://eim.example.test/gsma/rsp2/asn1`
- **Headers:**
  - `Content-Type: application/x-gsma-rsp-asn1`
  - `Accept: application/json, application/x-gsma-rsp-asn1`
  - `X-Admin-Protocol: gsma/rsp/v2.1.0` (if `EIM_HTTP_PROTOCOL` non-empty)

**Body (binary BER-TLV)**

- Single TLV: **GetEimPackage** (tag `BF 4F`) containing **EID** (tag `5A`).
- Build:
  - EID from the card is a BCD digit string (e.g. `89045967676472615349763031303005`).
  - Encoded to bytes: two digits per byte, high nibble first → 16 bytes for a 32-digit EID.
  - Inner TLV: `5A` + length (1 byte) + EID bytes → e.g. `5A 10 <16 bytes>`.
  - Outer TLV: `BF 4F` + length (1 byte) + inner TLV.
- Example (EID 16 bytes): request body hex starts with `BF 4F 12 5A 10` followed by 16 EID bytes (total 22 bytes).

`GetEimPackageRequest` (tag `BF4F`) ASN.1:
- **eidValue** [APPLICATION 26] Octet16 -- tag **5A** (sent).
- **notifyStateChange** [0] NULL OPTIONAL -- notify eIM to update eUICC info (e.g. profiles).
- **stateChangeCause** [1] StateChangeCause OPTIONAL.
- **rPLMN** [2] OCTET STRING (SIZE(3)) OPTIONAL -- MCC+MNC of last registered PLMN (3GPP TS 24.008).

The current build sends **only** EID (`5A`); `notifyStateChange [0]`, `stateChangeCause [1]`, and `rPLMN [2]` are **not** sent. Sending only EID may be why some eIMs return **undefinedError(127)** instead of `noEimPackageAvailable(1)`.

---

## 3. Incoming response (current behaviour)

**Observed:** 6 bytes, hex `BF 4F 03 02 01 7F`.

**Parsed as:**

- Tag: `BF 4F` (`GetEimPackageResponse` CHOICE).
- Length: `03`.
- Value: `02 01 7F` → DER INTEGER **127** = **eimPackageError ::= undefinedError(127)**.

The response is **not** `noEimPackageAvailable(1)` (no package); it is **undefinedError(127)** (generic error). The eIM is indicating an error condition, not "no packages available".

`GetEimPackageResponse` CHOICE (tag `BF4F`):
- `euiccPackageRequest [81]` (`BF51`), `ipaEuiccDataRequest [82]` (`BF52`), `profileDownloadTriggerRequest [84]` (`BF54`), or
- **`eimPackageError`** INTEGER `{ noEimPackageAvailable(1), eidNotFound(2), invalidEid(3), missingEid(4), undefinedError(127) }`

The simulator treats 127 as polling complete (no packages to ack) and does not send a follow-up. The root cause of the `undefinedError` may be the request (e.g. missing optional fields) or server state.

---

## 4. Response parsing (binary path)

- If the body does not start with `{`, it is treated as binary.
- BER-TLV parsing:
  - `GetEimPackageResponse` (`BF4F`) value INTEGER 127 → `eimPackageError undefinedError(127)`; `pollingComplete = True`, no packages.
  - Tag `04` (OCTET STRING) → treat value as one package (base64-encode and append to `euiccPackageList`).
  - Tag `0C` (IA5String) and value looks like base64 → append to package list.
  - Any constructed tag (e.g. `30`, `31`, `A0`-`A4`, `81`-`84`, `BF`) → recurse into value and merge out `euiccPackageList`, `transactionId`, `pollingComplete`.
- For `BF 4F 03 02 01 7F`: tag `BF` (first byte) plus the multi-byte tag continuation gives `BF 4F`, length 3, value `02 01 7F`. The parser does **not** treat `0F` as a result code (only tag byte `0x0F`). It recurses into `BF 4F`'s value; inside there is no TLV that maps to a package, and there is no special case for "inner value = INTEGER 127". The result is **packages = []** with default **`pollingComplete = True`**. (If the server sent a different structure with an explicit result code tag, mapping 127 → no packages / complete would still be needed.)

So for the **exact** 6-byte response:

- **Read path:** The response is read as one TLV, value = INTEGER 127. The parser does not set `pollingComplete` from inside `BF4F`; instead it finds no OCTET STRING packages, so the package list stays empty. "No packages" is correct; the only nuance is whether 127 should explicitly set `pollingComplete` when nested inside `BF4F` (an explicit rule could be added for clarity).

---

## 5. Continuation poll (when packages are present)

If the server had returned packages:

- The simulator would relay them to the card (`StoreData`) and obtain a card result (`euiccPackageResult`).
- The next request would be **JSON** (`raw_body = None`): same URL and headers, but body = JSON with at least `euiccPackageResult` (base64) and the other eIM fields (`eimFqdn`, `eimId`, `eid`, etc.) so the server can match the session and record the ack.

So the **first** request is binary (`GetEimPackage` with EID only); **subsequent** requests (if any) are JSON with `euiccPackageResult`.

---

## 6. Summary table

| Step | Outgoing | Incoming (current) |
|------|----------------|----------------------|
| 1    | POST ... body = `GetEimPackage` (`BF4F`) with EID (`5A`) only | 6 bytes: `BF 4F 03 02 01 7F` → **`eimPackageError undefinedError(127)`** (generic error, not `noEimPackageAvailable(1)`) |
| 2    | (Only if step 1 returned packages) JSON POST with `euiccPackageResult` + other fields | -- |

---

## 7. eimPackageError: 1 vs 127

`GetEimPackageResponse eimPackageError` INTEGER:
- **`noEimPackageAvailable(1)`** -- no package for this eUICC.
- `eidNotFound(2)`, `invalidEid(3)`, `missingEid(4)`.
- **`undefinedError(127)`** -- generic / undefined error.

Observed code is **127 (`undefinedError`)**, not 1 (`noEimPackageAvailable`). The eIM is returning a **generic error**, not "no package". A different server may log `NO_EIM_PACKAGE_AVAILABLE (1)`; this eIM returns 127 on the wire.

The simulator parses and logs the error by name (e.g. `eimPackageError=undefinedError(127)`). A natural follow-up is to add optional `GetEimPackageRequest` fields (`notifyStateChange [0]`, `stateChangeCause [1]`, `rPLMN [2]`) to see if the eIM then returns 1 instead of 127.

---

## 8. Clearing a stuck transaction ("clear ack")

If the **first** request left the eIM in a state where it keeps returning "no package" until the transaction is closed, the simulator may need to **acknowledge even when zero packages were returned** so the server can clear the session.

- **Current behaviour:** On `pollingComplete` with **no** packages, no follow-up is sent; the call returns immediately.
- **Optional behaviour:** With `EIM_CLEAR_ACK_ON_NO_PACKAGE=true`, on a no-packages response one JSON POST is sent with the same eIM fields and `euiccPackageResult=""` to signal "no packages received, transaction complete." The server may require this so the next `GetEimPackage` is not treated as a continuation of a hung transaction.

Config: `EIM_CLEAR_ACK_ON_NO_PACKAGE` (default `false`). When `true` and zero packages are returned, **`ProvideEimPackageResult`** (`BF50`) is sent with `eimPackageResultResponseError [0]` and `eimPackageResultErrorCode undefinedError(127)`, so the eIM can close the transaction. See `EIM_ESIPA_ASN1_REFERENCE.md` for the ESIPA message set.

Optional: `EIM_CLEAR_ACK_GENERIC_ERROR_HEX` -- custom hex TLV for the result (e.g. a different error code). If unset, the standard `ProvideEimPackageResult` error TLV (`BF50078005300302017F`) is used. If the server returned a `transactionId`, it is included in the clear-ack request.

---

## 9. Scenarios vs this sequence

1. **eIM does not hand over packages**
   The server could require something not currently sent (e.g. `euiccChallenge`, `eimId`, or registration). The first request contains only EID inside `GetEimPackage`; no challenge, no `eimId` in the binary body. It is therefore possible the server expects more in the request (or a different first step) before it returns packages.

2. **Response not parsed correctly**
   For the 6-byte response the parser does read it: one TLV, value = INTEGER 127. No packages are extracted because there are no OCTET STRINGs. An explicit rule could be added: "if `GetEimPackageResponse` (`BF4F`) value is INTEGER 127 (or 0), treat as no packages and polling complete."

3. **Request not formed correctly**
   If the server required a different or larger request, it would often respond with an HTTP error or a different result code. A clean **127** suggests the server understood the request and is explicitly saying "no package." The eIM may require optional `GetEimPackageRequest` fields (`notifyStateChange [0]`, `stateChangeCause [1]`, `rPLMN [2]`) so it returns 1 or a success branch instead of 127.

4. **Transaction left open**
   The first poll might put the server in a state where it keeps returning 127 until an explicit "no packages" ack is sent (see §8). Use `EIM_CLEAR_ACK_ON_NO_PACKAGE` to test.

---

## 10. References

- **ESIPA ASN.1:** `tests/eim-sh/EIM_ESIPA_ASN1_REFERENCE.md` -- `EsipaMessageFromIpaToEim` / `FromEimToIpa`, `GetEimPackageRequest`/`Response`, `ProvideEimPackageResult` (`BF50`), `EimPackageResult`, `EimPackageResultResponseError`.
- Request body build: `SCP11/orchestrator.py` → `_build_get_eim_package_tlv(eid)` (`BF4F`), `_build_provide_eim_package_result_error_tlv(127)` (`BF50` clear-ack).
- HTTP call: `SCP11/es9_client.py` → `poll_eim()` → `_post_eim_binary()` or JSON.
- Response parse: `_parse_eim_binary_response(raw)` (`eimPackageError`, packages, `pollingComplete`).
