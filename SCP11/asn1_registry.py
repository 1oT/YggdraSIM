# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""SCP11 ASN.1 registry: maps SGP.22 / SGP.32 OID arcs to pySim codec instances for ES2+/ES9+ message decoding."""
# -----------------------------------------------------------------------------
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
#
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
# -----------------------------------------------------------------------------

from asn1crypto import core, x509


class TransactionId(core.OctetString):
    class_, tag, method = 2, 0, 0


class EuiccChallenge(core.OctetString):
    class_, tag, method = 2, 1, 0


class ServerAddress(core.UTF8String):
    class_, tag, method = 2, 3, 0


class ServerChallenge(core.OctetString):
    class_, tag, method = 2, 4, 0


class ServerSignature(core.OctetString):
    class_, tag, method = 1, 55, 0


class EuiccSignature1(core.OctetString):
    class_, tag, method = 1, 55, 0


class VersionType(core.OctetString):
    pass


class ServerSigned1(core.Sequence):
    # transactionId context [0] (0x80) to match EuiccSigned1, SmdpSigned2, BF23 (SGP.22)
    _fields = [
        ("transactionId", TransactionId, {"tag_type": "context", "tag": 0}),
        ("euiccChallenge", EuiccChallenge),
        ("serverAddress", ServerAddress),
        ("serverChallenge", ServerChallenge),
    ]


# The RSP module is AUTOMATIC TAGS (SGP.22 v3.1 page 437): DeviceInfo and DeviceCapabilities members
# carry the context tag of their position, IMPLICIT, and CtxParamsForCommonAuthentication writes its
# [0] / [1] (page 449). Without them asn1crypto writes the universal tags ('0C', '30', '04'). The
# pySim codec is the encoder of record; this model is its fallback and must give the same bytes
# (tests/test_scp11_payloads.py). Members follow SGP.22 v3.1, page 441 (DeviceInfo) and page 442.
class DeviceAdditionalFeatureSupport(core.Sequence):
    _fields = [
        ("naiSupport", VersionType, {"implicit": 0, "optional": True}),
    ]


class DeviceCapabilities(core.Sequence):
    _fields = [
        ("gsmSupportedRelease", VersionType, {"implicit": 0, "optional": True}),
        ("utranSupportedRelease", VersionType, {"implicit": 1, "optional": True}),
        ("cdma2000onexSupportedRelease", VersionType, {"implicit": 2, "optional": True}),
        ("cdma2000hrpdSupportedRelease", VersionType, {"implicit": 3, "optional": True}),
        ("cdma2000ehrpdSupportedRelease", VersionType, {"implicit": 4, "optional": True}),
        ("eutranEpcSupportedRelease", VersionType, {"implicit": 5, "optional": True}),
        ("contactlessSupportedRelease", VersionType, {"implicit": 6, "optional": True}),
        ("rspCrlSupportedVersion", VersionType, {"implicit": 7, "optional": True}),
        ("nrEpcSupportedRelease", VersionType, {"implicit": 8, "optional": True}),
        ("nr5gcSupportedRelease", VersionType, {"implicit": 9, "optional": True}),
        ("eutran5gcSupportedRelease", VersionType, {"implicit": 10, "optional": True}),
        ("lpaSvn", VersionType, {"implicit": 11, "optional": True}),
        ("catSupportedClasses", core.BitString, {"implicit": 12, "optional": True}),
        ("euiccFormFactorType", core.Integer, {"implicit": 13, "optional": True}),
        ("deviceAdditionalFeatureSupport", DeviceAdditionalFeatureSupport, {"implicit": 14, "optional": True}),
    ]


class PreferredLanguages(core.SequenceOf):
    _child_spec = core.UTF8String


class DeviceInfo(core.Sequence):
    _fields = [
        ("tac", core.OctetString, {"implicit": 0}),
        ("deviceCapabilities", DeviceCapabilities, {"implicit": 1}),
        ("imei", core.OctetString, {"implicit": 2, "optional": True}),
        ("preferredLanguages", PreferredLanguages, {"implicit": 3, "optional": True}),
        ("deviceTestMode", core.Null, {"implicit": 4, "optional": True}),
        ("lpaRspCapability", core.BitString, {"implicit": 5, "optional": True}),
    ]


class CtxParamsForCommonAuthentication(core.Sequence):
    # ctxParamsForCommonAuthentication [0] of CtxParams1 (SGP.22 v3.1 page 449). The members
    # PayloadBuilder fills; operationType [2] (left at its DEFAULT, which DER omits), iccid,
    # matchingIdSource [3] and vendorSpecificExtension [4] are not modelled here.
    class_, tag, method = 2, 0, 1
    _fields = [
        ("matchingId", core.UTF8String, {"implicit": 0, "optional": True}),
        ("deviceInfo", DeviceInfo, {"implicit": 1}),
    ]


class CtxParams1(core.Choice):
    _alternatives = [
        ("ctxParamsForCommonAuthentication", CtxParamsForCommonAuthentication),
    ]


class AuthenticateServerRequest(core.Sequence):
    class_, tag = 2, 56
    _fields = [
        ("serverSigned1", ServerSigned1),
        ("serverSignature1", ServerSignature),
        ("euiccCiPKIdToBeUsed", core.OctetString, {"optional": True}),
        ("serverCertificate", x509.Certificate),
        ("ctxParams1", CtxParams1),
    ]


class EuiccSigned1(core.Sequence):
    _fields = [
        ("transactionId", TransactionId, {"tag_type": "context", "tag": 0}),
        ("serverAddress", ServerAddress, {"tag_type": "context", "tag": 3}),
        ("serverChallenge", ServerChallenge, {"tag_type": "context", "tag": 4}),
        ("euiccInfo2", core.Any, {"tag_type": "context", "tag": 34}),
        ("ctxParams1", CtxParams1),
    ]


class AuthenticateResponseOk(core.Sequence):
    class_, tag = 2, 0
    _fields = [
        ("euiccSigned1", EuiccSigned1),
        ("euiccSignature1", EuiccSignature1),
        ("euiccCertificate", x509.Certificate),
        ("nextCertInChain", x509.Certificate),
    ]


class AuthenticateResponseError(core.Integer):
    class_, tag = 2, 1


class AuthenticateServerResponse(core.Choice):
    _alternatives = [
        ("authenticateResponseOk", AuthenticateResponseOk),
        ("authenticateResponseError", AuthenticateResponseError),
    ]


class SmdpSigned2(core.Sequence):
    _fields = [
        ("transactionId", TransactionId, {"tag_type": "context", "tag": 0}),
        ("ccRequiredFlag", core.Boolean),
        ("bppEuiccOtpk", core.OctetString, {"tag_type": "application", "tag": 73, "optional": True}),
    ]


class PrepareDownloadRequest(core.Sequence):
    class_, tag = 2, 33
    _fields = [
        ("smdpSigned2", SmdpSigned2),
        ("smdpSignature2", core.OctetString, {"tag_type": "application", "tag": 55}),
        ("hashCc", core.OctetString, {"optional": True}),
        ("smdpCertificate", x509.Certificate),
    ]


class ASN1Registry:
    """Namespace wrapper for compatibility with existing imports."""

    TransactionId = TransactionId
    EuiccChallenge = EuiccChallenge
    ServerAddress = ServerAddress
    ServerChallenge = ServerChallenge
    ServerSignature = ServerSignature
    EuiccSignature1 = EuiccSignature1
    VersionType = VersionType
    ServerSigned1 = ServerSigned1
    DeviceCapabilities = DeviceCapabilities
    DeviceInfo = DeviceInfo
    CtxParamsForCommonAuthentication = CtxParamsForCommonAuthentication
    CtxParams1 = CtxParams1
    AuthenticateServerRequest = AuthenticateServerRequest
    EuiccSigned1 = EuiccSigned1
    AuthenticateResponseOk = AuthenticateResponseOk
    AuthenticateResponseError = AuthenticateResponseError
    AuthenticateServerResponse = AuthenticateServerResponse
    SmdpSigned2 = SmdpSigned2
    PrepareDownloadRequest = PrepareDownloadRequest
