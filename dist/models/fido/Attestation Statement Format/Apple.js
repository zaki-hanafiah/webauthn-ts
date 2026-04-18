"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.AppleVerify = exports.isAppleAttestation = void 0;
const crypto_1 = __importDefault(require("crypto"));
const x509_1 = require("@fidm/x509");
function isAppleAttestation(obj) {
    if (obj['fmt'] &&
        obj['fmt'] === 'apple' &&
        obj['attStmt'] &&
        Array.isArray(obj['attStmt']['x5c']) &&
        obj['attStmt']['x5c'].length > 0)
        return true;
    return false;
}
exports.isAppleAttestation = isAppleAttestation;
function AppleVerify(attestation, clientDataHash, authenticatorData) {
    const attStmt = attestation.attStmt;
    const credCertPem = '-----BEGIN CERTIFICATE-----\n' +
        attStmt.x5c[0].toString('base64') +
        '\n-----END CERTIFICATE-----';
    const credCert = x509_1.Certificate.fromPEM(Buffer.from(credCertPem));
    const verificationData = Buffer.concat([attestation.authData, clientDataHash]);
    const expectedNonce = crypto_1.default
        .createHash('sha256')
        .update(verificationData)
        .digest();
    const appleExtension = credCert.extensions.find((ext) => ext.oid === '1.2.840.113635.100.8.2');
    if (!appleExtension)
        return false;
    const nonceFromCert = extractAppleNonce(appleExtension.value);
    if (!nonceFromCert)
        return false;
    if (!expectedNonce.equals(nonceFromCert))
        return false;
    if (!verifyPublicKeyMatch(credCertPem, authenticatorData))
        return false;
    return true;
}
exports.AppleVerify = AppleVerify;
function extractAppleNonce(extensionValue) {
    try {
        let offset = 0;
        if (extensionValue[offset++] !== 0x30)
            return null;
        offset += derLengthBytes(extensionValue, offset);
        if (extensionValue[offset++] !== 0x30)
            return null;
        offset += derLengthBytes(extensionValue, offset);
        if (extensionValue[offset++] !== 0x04)
            return null;
        const len = extensionValue[offset++];
        return extensionValue.slice(offset, offset + len);
    }
    catch (_a) {
        return null;
    }
}
function derLengthBytes(buf, offset) {
    const first = buf[offset];
    if (first <= 0x7f)
        return 1;
    return 1 + (first & 0x7f);
}
function verifyPublicKeyMatch(certPem, authenticatorData) {
    try {
        const credPubKey = authenticatorData.attestedCredentialData.credentialPublicKey;
        const certKey = crypto_1.default.createPublicKey(certPem);
        const certKeyJwk = certKey.export({ format: 'jwk' });
        if (credPubKey.kty === 'EC') {
            if (!credPubKey.x || !credPubKey.y || !certKeyJwk.x || !certKeyJwk.y)
                return false;
            return (certKeyJwk.kty === 'EC' &&
                Buffer.from(certKeyJwk.x, 'base64').equals(Buffer.from(credPubKey.x, 'base64')) &&
                Buffer.from(certKeyJwk.y, 'base64').equals(Buffer.from(credPubKey.y, 'base64')));
        }
        else if (credPubKey.kty === 'RSA') {
            if (!credPubKey.n || !credPubKey.e || !certKeyJwk.n || !certKeyJwk.e)
                return false;
            return (certKeyJwk.kty === 'RSA' &&
                Buffer.from(certKeyJwk.n, 'base64').equals(Buffer.from(credPubKey.n, 'base64')) &&
                Buffer.from(certKeyJwk.e, 'base64').equals(Buffer.from(credPubKey.e, 'base64')));
        }
        return false;
    }
    catch (_a) {
        return false;
    }
}
//# sourceMappingURL=Apple.js.map