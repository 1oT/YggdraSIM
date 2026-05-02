# ESIPA ASN.1 reference (eIM ↔ IPA)

Abbreviated reference for ESIPA message set. SGP.32 / GSMA.

---

## EsipaMessageFromIpaToEim (IPA → eIM)

CHOICE:
- initiateAuthenticationRequestEsipa [57] -- Tag BF39
- authenticateClientRequestEsipa [59] -- Tag BF3B
- getBoundProfilePackageRequestEsipa [58] -- Tag BF3A
- cancelSessionRequestEsipa [65] -- Tag BF41
- handleNotificationEsipa [61] -- Tag BF3D
- transferEimPackageResponse [78] -- Tag BF4E
- **getEimPackageRequest [79]** -- Tag **BF4F**
- **provideEimPackageResult [80]** -- Tag **BF50**

---

## EsipaMessageFromEimToIpa (eIM → IPA)

CHOICE:
- initiateAuthenticationResponseEsipa [57] -- Tag BF39
- authenticateClientResponseEsipa [59] -- Tag BF3B
- getBoundProfilePackageResponseEsipa [58] -- Tag BF3A
- cancelSessionResponseEsipa [65] -- Tag BF41
- transferEimPackageRequest [78] -- Tag BF4E
- **getEimPackageResponse [79]** -- Tag **BF4F**
- **provideEimPackageResultResponse [80]** -- Tag **BF50**

---

## GetEimPackageRequest ::= [79] SEQUENCE -- Tag BF4F

- eidValue [APPLICATION 26] Octet16 -- Tag 5A
- notifyStateChange [0] NULL OPTIONAL
- stateChangeCause [1] StateChangeCause OPTIONAL
- rPLMN [2] OCTET STRING (SIZE(3)) OPTIONAL

StateChangeCause ::= INTEGER {
  otherEim(0), fallback(1), emergencyProfile(2), local(3), reset(4),
  immediateEnableProfile(5), deviceChange(6), undefined(127) }

---

## GetEimPackageResponse ::= [79] CHOICE -- Tag BF4F

- euiccPackageRequest [81] -- Tag BF51
- ipaEuiccDataRequest [82] -- Tag BF52
- profileDownloadTriggerRequest [84] -- Tag BF54
- eimPackageError INTEGER {
    noEimPackageAvailable(1), eidNotFound(2), invalidEid(3), missingEid(4), undefinedError(127) }

---

## ProvideEimPackageResult ::= [80] SEQUENCE -- Tag BF50

Sent by IPA to eIM to provide the result of processing an eIM package (or to signal error / clear).

- eidValue [APPLICATION 26] Octet16 OPTIONAL -- Tag 5A
- **eimPackageResult** EimPackageResult

---

## EimPackageResult ::= CHOICE

- euiccPackageResult [81] EuiccPackageResult -- Tag BF51
- ePRAndNotifications SEQUENCE { euiccPackageResult [81], notificationList [0] }
- ipaEuiccDataResponse [82] IpaEuiccDataResponse -- Tag BF52 (CHOICE: ipaEuiccData [0] tag A0, ipaEuiccDataResponseError [1] tag A1)
- profileDownloadTriggerResult [84] -- Tag BF54
- **eimPackageResultResponseError [0]** EimPackageResultResponseError

---

## EimPackageResultResponseError ::= SEQUENCE

- eimTransactionId [0] TransactionId OPTIONAL
- **eimPackageResultErrorCode** EimPackageResultErrorCode

EimPackageResultErrorCode ::= INTEGER {
  invalidPackageFormat(1), unknownPackage(2), **undefinedError(127)** }

---

## ProvideEimPackageResultResponse ::= [80] CHOICE -- Tag BF50

- eimAcknowledgements [83] -- Tag BF53
- emptyResponse SEQUENCE {}
- provideEimPackageResultError INTEGER {
    eidNotFound(2), invalidEid(3), missingEid(4), undefinedError(127) }

---

## Minimal clear-ack / error (no packages)

To signal to the eIM that no package is available or an error occurred (so it can close the transaction), send **ProvideEimPackageResult** (BF50) with **EimPackageResult** = **eimPackageResultResponseError [0]**:

- eimPackageResultResponseError [0]: SEQUENCE { eimPackageResultErrorCode = undefinedError(127) }
- BER (minimal, no eidValue, no eimTransactionId):  
  **BF 50 07 80 05 30 03 02 01 7F**

Hex: `BF50078005300302017F`

When sending via JSON (ESIPA REST binding), `euiccPackageResult` (or the equivalent field for the result) may carry base64 of this BER so the eIM receives a proper ProvideEimPackageResult.
