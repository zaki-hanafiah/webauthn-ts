"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.TPMVerify = exports.isTPMAttestation = void 0;
const crypto_1 = __importDefault(require("crypto"));
const util = __importStar(require("../../../authentication/util"));
const x509_1 = require("@fidm/x509");
function isTPMAttestation(obj) {
    if (obj['fmt'] &&
        obj['fmt'] === 'tpm' &&
        obj['attStmt'] &&
        obj['attStmt']['ver'] === '2.0' &&
        obj['attStmt']['alg'] &&
        obj['attStmt']['sig'] &&
        obj['attStmt']['certInfo'] &&
        obj['attStmt']['pubArea'])
        return true;
    return false;
}
exports.isTPMAttestation = isTPMAttestation;
function TPMVerify(attestation, attStmt, clientDataHash, authenticatorData) {
    if (attStmt.ver !== '2.0')
        return false;
    const certInfo = util.parseCertInfo(attStmt.certInfo);
    const pubArea = util.parsePubArea(attStmt.pubArea);
    if (certInfo.magic !== 0xff544347)
        return false;
    if (certInfo.type !== 'TPM_ST_ATTEST_CERTIFY')
        return false;
    const sigHashAlg = algToHash(attStmt.alg);
    if (!sigHashAlg) {
        util.algorithmWarning(attStmt.alg);
        return false;
    }
    const verificationData = Buffer.concat([attestation.authData, clientDataHash]);
    const expectedExtraData = crypto_1.default
        .createHash(sigHashAlg)
        .update(verificationData)
        .digest();
    if (!expectedExtraData.equals(certInfo.extraData))
        return false;
    const nameHashAlg = tpmAlgToHash(certInfo.attested.nameAlg);
    if (!nameHashAlg)
        return false;
    const pubAreaHash = crypto_1.default
        .createHash(nameHashAlg)
        .update(attStmt.pubArea)
        .digest();
    const nameHashBytes = certInfo.attested.name.slice(2);
    if (!pubAreaHash.equals(nameHashBytes))
        return false;
    if (attStmt.x5c) {
        const x5cString = attStmt.x5c[0].toString('base64');
        const certPem = '-----BEGIN CERTIFICATE-----\n' +
            x5cString +
            '\n-----END CERTIFICATE-----';
        const cert = x509_1.Certificate.fromPEM(Buffer.from(certPem));
        if (!validateAikCert(cert))
            return false;
        const cryptoAlg = algToCryptoAlg(attStmt.alg);
        if (!cryptoAlg) {
            util.algorithmWarning(attStmt.alg);
            return false;
        }
        const verifier = crypto_1.default.createVerify(cryptoAlg);
        verifier.update(attStmt.certInfo);
        if (!verifier.verify(certPem, attStmt.sig))
            return false;
    }
    else if (attStmt.ecdaaKeyId) {
        util.ecdaaWarning();
        return false;
    }
    else {
        return false;
    }
    return true;
}
exports.TPMVerify = TPMVerify;
function validateAikCert(cert) {
    var _a, _b;
    if (cert.version !== 3)
        return false;
    if (((_b = (_a = cert.subject) === null || _a === void 0 ? void 0 : _a.attributes) === null || _b === void 0 ? void 0 : _b.length) > 0)
        return false;
    const basicConstraints = cert.extensions.find((ext) => ext.name === 'basicConstraints');
    if (basicConstraints === null || basicConstraints === void 0 ? void 0 : basicConstraints.isCA)
        return false;
    const ekuExtension = cert.extensions.find((ext) => ext.oid === '2.5.29.37');
    if (!ekuExtension)
        return false;
    const aikOidBytes = Buffer.from([0x67, 0x81, 0x05, 0x08, 0x03]);
    if (ekuExtension.value && ekuExtension.value.indexOf(aikOidBytes) === -1) {
        console.warn('TPM AIK certificate EKU does not contain tcg-kp-AIKCertificate (2.23.133.8.3)');
        return false;
    }
    return true;
}
function algToHash(alg) {
    switch (alg) {
        case -7:
        case -37:
        case -257:
            return 'sha256';
        case -35:
        case -38:
        case -258:
            return 'sha384';
        case -36:
        case -39:
        case -259:
            return 'sha512';
        default:
            return null;
    }
}
function algToCryptoAlg(alg) {
    switch (alg) {
        case -7:
            return 'SHA256';
        case -35:
            return 'SHA384';
        case -36:
            return 'SHA512';
        case -257:
            return 'RSA-SHA256';
        case -258:
            return 'RSA-SHA384';
        case -259:
            return 'RSA-SHA512';
        default:
            return null;
    }
}
function tpmAlgToHash(nameAlg) {
    switch (nameAlg) {
        case 'TPM_ALG_SHA':
        case 'TPM_ALG_SHA1':
            return 'sha1';
        case 'TPM_ALG_SHA256':
            return 'sha256';
        case 'TPM_ALG_SHA384':
            return 'sha384';
        case 'TPM_ALG_SHA512':
            return 'sha512';
        default:
            return null;
    }
}
//# sourceMappingURL=TPM.js.map