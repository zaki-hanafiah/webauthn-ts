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
exports.PackedVerify = exports.isPackedAttestation = void 0;
const crypto_1 = __importDefault(require("crypto"));
const util = __importStar(require("../../../authentication/util"));
const x509_1 = require("@fidm/x509");
function isPackedAttestation(obj) {
    if (obj['fmt'] &&
        obj['fmt'] === 'packed' &&
        obj['attStmt'] &&
        obj['attStmt']['alg'] &&
        (obj['attStmt']['x5c'] || obj['attStmt']['ecdaaKeyId']) &&
        obj['attStmt']['sig'])
        return true;
    return false;
}
exports.isPackedAttestation = isPackedAttestation;
function PackedVerify(attestation, attStmt, clientDataHash, authenticatorData) {
    if (attStmt.x5c) {
        let x5cString = attStmt.x5c[0].toString('base64');
        let cert = '-----BEGIN CERTIFICATE-----\n' +
            x5cString +
            '\n-----END CERTIFICATE-----';
        if (attStmt.alg != -7)
            util.algorithmWarning(attStmt.alg);
        else {
            const verify = crypto_1.default.createVerify('RSA-SHA256');
            verify.update(attestation.authData);
            verify.update(clientDataHash);
            if (!verify.verify(cert, attStmt.sig))
                return false;
        }
        const decryptCert = x509_1.Certificate.fromPEM(Buffer.from(cert));
        if (!validatex509Cert(decryptCert))
            return false;
    }
    else if (attStmt.ecdaaKeyId) {
        console.warn(util.ecdaaWarning());
    }
    else {
    }
    return true;
}
exports.PackedVerify = PackedVerify;
function validatex509Cert(cert) {
    if (!(cert.version === 3))
        return false;
    let subjectC = cert.subject.attributes.find((attr) => {
        return attr.shortName === 'C';
    });
    let subjectO = cert.subject.attributes.find((attr) => {
        return attr.shortName === 'O';
    });
    let subjectOU = cert.subject.attributes.find((attr) => {
        return attr.shortName === 'OU';
    });
    let subjectCN = cert.subject.attributes.find((attr) => {
        return attr.shortName === 'CN';
    });
    if (!(subjectC &&
        subjectO &&
        subjectCN &&
        subjectOU &&
        subjectOU.value === 'Authenticator Attestation'))
        return false;
    let aaguidExtension = cert.extensions.find((ext) => {
        return ext.oid === '1.3.6.1.4.1.45724.1.1.4';
    });
    if (aaguidExtension) {
        let valOct = aaguidExtension.value.toString('base64');
        if (aaguidExtension.critical)
            return false;
    }
    const basicConstraints = cert.extensions.find((extension) => {
        return extension.name === 'basicConstraints';
    });
    if (basicConstraints && basicConstraints.isCA)
        return false;
    return true;
}
//# sourceMappingURL=Packed.js.map