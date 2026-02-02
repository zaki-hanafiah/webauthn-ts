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
exports.algorithmWarning = exports.ecdaaWarning = exports.parsePubArea = exports.parseCertInfo = exports.sha256 = exports.coseToJwk = exports.generatePublicKeyCredentialRequestOptions = exports.testCreateCreds = exports.generatePublicKeyCredentialCreationOptions = exports.parseAuthenticatorData = void 0;
const crypto_1 = __importDefault(require("crypto"));
const store = __importStar(require("../storage/persistentKeyStore"));
const uuid = __importStar(require("uuid-parse"));
const CBOR = __importStar(require("cbor"));
function parseAuthenticatorData(authData) {
    try {
        const authenticatorData = {};
        authenticatorData.rpIdHash = authData.slice(0, 32);
        authenticatorData.flags = authData[32];
        authenticatorData.signCount =
            (authData[33] << 24) |
                (authData[34] << 16) |
                (authData[35] << 8) |
                authData[36];
        if (authenticatorData.flags & 64) {
            const attestedCredentialData = {};
            attestedCredentialData.aaguid = uuid
                .unparse(authData.slice(37, 53))
                .toUpperCase();
            attestedCredentialData.credentialIdLength =
                (authData[53] << 8) | authData[54];
            attestedCredentialData.credentialId = authData.slice(55, 55 + attestedCredentialData.credentialIdLength);
            const publicKeyCoseBuffer = authData.slice(55 + attestedCredentialData.credentialIdLength, authData.length);
            attestedCredentialData.credentialPublicKey =
                coseToJwk(publicKeyCoseBuffer);
            authenticatorData.attestedCredentialData = attestedCredentialData;
        }
        if (authenticatorData.flags & 128) {
            let extensionDataCbor;
            if (authenticatorData.attestedCredentialData) {
                extensionDataCbor = CBOR.decodeAllSync(authData.slice(55 +
                    authenticatorData.attestedCredentialData
                        .credentialIdLength, authData.length));
                extensionDataCbor = extensionDataCbor[1];
            }
            else {
                extensionDataCbor = CBOR.decodeFirstSync(authData.slice(37, authData.length));
            }
            authenticatorData.extensionData =
                CBOR.encode(extensionDataCbor).toString('base64');
        }
        return authenticatorData;
    }
    catch (e) {
        throw new Error('Authenticator Data could not be parsed');
    }
}
exports.parseAuthenticatorData = parseAuthenticatorData;
function generatePublicKeyCredentialCreationOptions() {
    return {
        challenge: generateChallenge(),
        rp: {
            name: process.env.RPNAME,
            id: process.env.RPID,
        },
        user: {
            id: '',
            name: '',
            displayName: '',
        },
        pubKeyCredParams: [
            { alg: -7, type: 'public-key' },
            { alg: -8, type: 'public-key' },
            { alg: -35, type: 'public-key' },
            { alg: -36, type: 'public-key' },
            { alg: -37, type: 'public-key' },
            { alg: -38, type: 'public-key' },
            { alg: -39, type: 'public-key' },
            { alg: -257, type: 'public-key' },
            { alg: -258, type: 'public-key' },
            { alg: -259, type: 'public-key' },
        ],
        authenticatorSelection: {
            requireResidentKey: false,
            userVerification: 'discouraged',
        },
        timeout: 60000,
        attestation: 'indirect',
    };
}
exports.generatePublicKeyCredentialCreationOptions = generatePublicKeyCredentialCreationOptions;
function testCreateCreds() {
    return {
        attestation: 'indirect',
        authenticatorSelection: {
            requireResidentKey: true,
            userVerification: 'discouraged',
        },
        challenge: generateChallenge(),
        pubKeyCredParams: [
            { type: 'public-key', alg: -7 },
            { type: 'public-key', alg: -35 },
            { type: 'public-key', alg: -36 },
            { type: 'public-key', alg: -257 },
            { type: 'public-key', alg: -258 },
            { type: 'public-key', alg: -259 },
            { type: 'public-key', alg: -37 },
            { type: 'public-key', alg: -38 },
            { type: 'public-key', alg: -39 },
            { type: 'public-key', alg: -8 },
        ],
        rp: {
            id: process.env.RPID,
            name: process.env.RPNAME,
        },
        timeout: 60000,
        user: {
            id: '',
            name: '',
            displayName: '',
        },
    };
}
exports.testCreateCreds = testCreateCreds;
function generatePublicKeyCredentialRequestOptions(userId) {
    var _a;
    return {
        challenge: generateChallenge(),
        timeout: 60000,
        rpId: process.env.RPID,
        allowCredentials: [{ type: 'public-key', id: (_a = store.get(userId)) === null || _a === void 0 ? void 0 : _a.id }],
    };
}
exports.generatePublicKeyCredentialRequestOptions = generatePublicKeyCredentialRequestOptions;
function coseToJwk(cose) {
    try {
        let publicKeyJwk = {};
        const publicKeyCbor = CBOR.decodeFirstSync(cose);
        if (publicKeyCbor.get(3) == -7) {
            publicKeyJwk = {
                kty: 'EC',
                crv: 'P-256',
                x: publicKeyCbor.get(-2).toString('base64'),
                y: publicKeyCbor.get(-3).toString('base64'),
            };
        }
        else if (publicKeyCbor.get(3) == -257) {
            publicKeyJwk = {
                kty: 'RSA',
                n: publicKeyCbor.get(-1).toString('base64'),
                e: publicKeyCbor.get(-2).toString('base64'),
            };
        }
        else {
            throw new Error('Unknown public key algorithm');
        }
        return publicKeyJwk;
    }
    catch (e) {
        throw new Error('Could not decode COSE Key');
    }
}
exports.coseToJwk = coseToJwk;
function sha256(data) {
    const hash = crypto_1.default.createHash('sha256');
    hash.update(data);
    return hash.digest();
}
exports.sha256 = sha256;
function generateChallenge() {
    let charPool = '1234567890qwertzuiopasdfghjklyxcvbnm';
    let rString = '';
    for (let i = 0; i < 32; i++) {
        rString += charPool.charAt(Math.floor(Math.random() * charPool.length));
    }
    return rString;
}
function base64encode(string) {
    let buff = Buffer.from(string);
    let base64String = buff.toString('base64');
    return base64String.substring(0, base64String.length - 1);
}
function parseCertInfo(certInfoBuffer) {
    let magicBuffer = certInfoBuffer.slice(0, 4);
    let magic = magicBuffer.readUInt32BE(0);
    certInfoBuffer = certInfoBuffer.slice(4);
    let typeBuffer = certInfoBuffer.slice(0, 2);
    let type = TPM_ST[typeBuffer.readUInt16BE(0)];
    certInfoBuffer = certInfoBuffer.slice(2);
    let qualifiedSignerLength = certInfoBuffer.slice(0, 2).readUInt16BE(0);
    certInfoBuffer = certInfoBuffer.slice(2);
    let qualifiedSigner = certInfoBuffer.slice(0, qualifiedSignerLength);
    certInfoBuffer = certInfoBuffer.slice(qualifiedSignerLength);
    let extraDataLength = certInfoBuffer.slice(0, 2).readUInt16BE(0);
    certInfoBuffer = certInfoBuffer.slice(2);
    let extraData = certInfoBuffer.slice(0, extraDataLength);
    certInfoBuffer = certInfoBuffer.slice(extraDataLength);
    let clockInfo = {
        clock: certInfoBuffer.slice(0, 8),
        resetCount: certInfoBuffer.slice(8, 12).readUInt32BE(0),
        restartCount: certInfoBuffer.slice(12, 16).readUInt32BE(0),
        safe: !!certInfoBuffer[16],
    };
    certInfoBuffer = certInfoBuffer.slice(17);
    let firmwareVersion = certInfoBuffer.slice(0, 8);
    certInfoBuffer = certInfoBuffer.slice(8);
    let attestedNameBufferLength = certInfoBuffer.slice(0, 2).readUInt16BE(0);
    let attestedNameBuffer = certInfoBuffer.slice(2, attestedNameBufferLength + 2);
    certInfoBuffer = certInfoBuffer.slice(2 + attestedNameBufferLength);
    let attestedQualifiedNameBufferLength = certInfoBuffer
        .slice(0, 2)
        .readUInt16BE(0);
    let attestedQualifiedNameBuffer = certInfoBuffer.slice(2, attestedQualifiedNameBufferLength + 2);
    certInfoBuffer = certInfoBuffer.slice(2 + attestedQualifiedNameBufferLength);
    let attested = {
        nameAlg: TPM_ALG[attestedNameBuffer.slice(0, 2).readUInt16BE(0)],
        name: attestedNameBuffer,
        qualifiedName: attestedQualifiedNameBuffer,
    };
    return {
        magic,
        type,
        qualifiedSigner,
        extraData,
        clockInfo,
        firmwareVersion,
        attested,
    };
}
exports.parseCertInfo = parseCertInfo;
function parsePubArea(pubAreaBuffer) {
    let typeBuffer = pubAreaBuffer.slice(0, 2);
    let type = TPM_ALG[typeBuffer.readUInt16BE(0)];
    pubAreaBuffer = pubAreaBuffer.slice(2);
    let nameAlgBuffer = pubAreaBuffer.slice(0, 2);
    let nameAlg = TPM_ALG[nameAlgBuffer.readUInt16BE(0)];
    pubAreaBuffer = pubAreaBuffer.slice(2);
    let objectAttributesBuffer = pubAreaBuffer.slice(0, 4);
    let objectAttributesInt = objectAttributesBuffer.readUInt32BE(0);
    let objectAttributes = {
        fixedTPM: !!(objectAttributesInt & 1),
        stClear: !!(objectAttributesInt & 2),
        fixedParent: !!(objectAttributesInt & 8),
        sensitiveDataOrigin: !!(objectAttributesInt & 16),
        userWithAuth: !!(objectAttributesInt & 32),
        adminWithPolicy: !!(objectAttributesInt & 64),
        noDA: !!(objectAttributesInt & 512),
        encryptedDuplication: !!(objectAttributesInt & 1024),
        restricted: !!(objectAttributesInt & 32768),
        decrypt: !!(objectAttributesInt & 65536),
        signORencrypt: !!(objectAttributesInt & 131072),
    };
    pubAreaBuffer = pubAreaBuffer.slice(4);
    let authPolicyLength = pubAreaBuffer.slice(0, 2).readUInt16BE(0);
    pubAreaBuffer = pubAreaBuffer.slice(2);
    let authPolicy = pubAreaBuffer.slice(0, authPolicyLength);
    pubAreaBuffer = pubAreaBuffer.slice(authPolicyLength);
    let parameters = undefined;
    if (type === 'TPM_ALG_RSA') {
        parameters = {
            symmetric: TPM_ALG[pubAreaBuffer.slice(0, 2).readUInt16BE(0)],
            scheme: TPM_ALG[pubAreaBuffer.slice(2, 4).readUInt16BE(0)],
            keyBits: pubAreaBuffer.slice(4, 6).readUInt16BE(0),
            exponent: pubAreaBuffer.slice(6, 10).readUInt32BE(0),
        };
        pubAreaBuffer = pubAreaBuffer.slice(10);
    }
    else if (type === 'TPM_ALG_ECC') {
        parameters = {
            symmetric: TPM_ALG[pubAreaBuffer.slice(0, 2).readUInt16BE(0)],
            scheme: TPM_ALG[pubAreaBuffer.slice(2, 4).readUInt16BE(0)],
            curveID: TPM_ECC_CURVE[pubAreaBuffer.slice(4, 6).readUInt16BE(0)],
            kdf: TPM_ALG[pubAreaBuffer.slice(6, 8).readUInt16BE(0)],
        };
        pubAreaBuffer = pubAreaBuffer.slice(8);
    }
    else
        throw new Error(type + ' is an unsupported type!');
    let uniqueLength = pubAreaBuffer.slice(0, 2).readUInt16BE(0);
    pubAreaBuffer = pubAreaBuffer.slice(2);
    let unique = pubAreaBuffer.slice(0, uniqueLength);
    pubAreaBuffer = pubAreaBuffer.slice(uniqueLength);
    return {
        type,
        nameAlg,
        objectAttributes,
        authPolicy,
        parameters,
        unique,
    };
}
exports.parsePubArea = parsePubArea;
function getEndian() {
    let arrayBuffer = new ArrayBuffer(2);
    let uint8Array = new Uint8Array(arrayBuffer);
    let uint16array = new Uint16Array(arrayBuffer);
    uint8Array[0] = 0xaa;
    uint8Array[1] = 0xbb;
    if (uint16array[0] === 0xbbaa)
        return 'little';
    else
        return 'big';
}
function readBE16(buffer) {
    if (buffer.length !== 2)
        throw new Error('Only 2byte buffer allowed!');
    if (getEndian() !== 'big')
        buffer = buffer.reverse();
    return new Uint16Array(buffer.buffer)[0];
}
function readBE32(buffer) {
    if (buffer.length !== 4)
        throw new Error('Only 4byte buffers allowed!');
    if (getEndian() !== 'big')
        buffer = buffer.reverse();
    return new Uint32Array(buffer.buffer)[0];
}
function ecdaaWarning() {
    console.warn('Your clients TPM module is using an ECDAA key to encrypt its verification data. ECDAA verification is not yet supported in this framework and will be implemented in a further release. If you want to support the development of this library, please create an issue on the GitHub repository with the following information:\n\n ECDAA Verification not supported!\nClient machine: <your-device>\nAuthentication method used: <e.g. Windows Hello, Apple Touch ID, ...>');
}
exports.ecdaaWarning = ecdaaWarning;
function algorithmWarning(alg) {
    console.warn('The authenticator is using an algorithm which is not supported to encrypt its signature. This is a shortcoming of this library and will be fixed in further releases. If you want to support the development of this library, please create an issue on the GitHub repository with following information:\n\n TPM Verification Algorithm not supported!\nAlgorithm: ' +
        alg);
}
exports.algorithmWarning = algorithmWarning;
let TPM_ALG = {
    0x0000: 'TPM_ALG_ERROR',
    0x0001: 'TPM_ALG_RSA',
    0x0003: 'TPM_ALG_SHA',
    0x0004: 'TPM_ALG_SHA1',
    0x0005: 'TPM_ALG_HMAC',
    0x0006: 'TPM_ALG_AES',
    0x0007: 'TPM_ALG_MGF1',
    0x0008: 'TPM_ALG_KEYEDHASH',
    0x000a: 'TPM_ALG_XOR',
    0x000b: 'TPM_ALG_SHA256',
    0x000c: 'TPM_ALG_SHA384',
    0x000d: 'TPM_ALG_SHA512',
    0x0010: 'TPM_ALG_NULL',
    0x0012: 'TPM_ALG_SM3_256',
    0x0013: 'TPM_ALG_SM4',
    0x0014: 'TPM_ALG_RSASSA',
    0x0015: 'TPM_ALG_RSAES',
    0x0016: 'TPM_ALG_RSAPSS',
    0x0017: 'TPM_ALG_OAEP',
    0x0018: 'TPM_ALG_ECDSA',
    0x0019: 'TPM_ALG_ECDH',
    0x001a: 'TPM_ALG_ECDAA',
    0x001b: 'TPM_ALG_SM2',
    0x001c: 'TPM_ALG_ECSCHNORR',
    0x001d: 'TPM_ALG_ECMQV',
    0x0020: 'TPM_ALG_KDF1_SP800_56A',
    0x0021: 'TPM_ALG_KDF2',
    0x0022: 'TPM_ALG_KDF1_SP800_108',
    0x0023: 'TPM_ALG_ECC',
    0x0025: 'TPM_ALG_SYMCIPHER',
    0x0026: 'TPM_ALG_CAMELLIA',
    0x0040: 'TPM_ALG_CTR',
    0x0041: 'TPM_ALG_OFB',
    0x0042: 'TPM_ALG_CBC',
    0x0043: 'TPM_ALG_CFB',
    0x0044: 'TPM_ALG_ECB',
};
let TPM_ECC_CURVE = {
    0x0000: 'TPM_ECC_NONE',
    0x0001: 'TPM_ECC_NIST_P192',
    0x0002: 'TPM_ECC_NIST_P224',
    0x0003: 'TPM_ECC_NIST_P256',
    0x0004: 'TPM_ECC_NIST_P384',
    0x0005: 'TPM_ECC_NIST_P521',
    0x0010: 'TPM_ECC_BN_P256',
    0x0011: 'TPM_ECC_BN_P638',
    0x0020: 'TPM_ECC_SM2_P256',
};
let TPM_ST = {
    0x00c4: 'TPM_ST_RSP_COMMAND',
    0x8000: 'TPM_ST_NULL',
    0x8001: 'TPM_ST_NO_SESSIONS',
    0x8002: 'TPM_ST_SESSIONS',
    0x8014: 'TPM_ST_ATTEST_NV',
    0x8015: 'TPM_ST_ATTEST_COMMAND_AUDIT',
    0x8016: 'TPM_ST_ATTEST_SESSION_AUDIT',
    0x8017: 'TPM_ST_ATTEST_CERTIFY',
    0x8018: 'TPM_ST_ATTEST_QUOTE',
    0x8019: 'TPM_ST_ATTEST_TIME',
    0x801a: 'TPM_ST_ATTEST_CREATION',
    0x8021: 'TPM_ST_CREATION',
    0x8022: 'TPM_ST_VERIFIED',
    0x8023: 'TPM_ST_AUTH_SECRET',
    0x8024: 'TPM_ST_HASHCHECK',
    0x8025: 'TPM_ST_AUTH_SIGNED',
    0x8029: 'TPM_ST_FU_MANIFEST',
};
//# sourceMappingURL=util.js.map