import { GenericAttestation } from '../../custom/GenericAttestation'
import { AuthenticatorData } from '../AuthenticatorData'
import crypto from 'crypto'
import * as util from '../../../authentication/util'
import { Certificate } from '@fidm/x509'
import { x5cInterface } from '../../custom/x5cCertificate'

/**
 * Specification: https://w3c.github.io/webauthn/#sctn-tpm-attestation
 */
export interface TPMAttestation extends GenericAttestation {
    fmt: 'tpm'
    attStmt: TPMStmt
}

export interface TPMStmt {
    ver: '2.0'
    alg: number
    x5c?: Array<Buffer>
    ecdaaKeyId?: Buffer
    sig: Buffer
    certInfo: Buffer
    pubArea: Buffer
}

export function isTPMAttestation(obj: { [key: string]: any }): boolean {
    if (
        obj['fmt'] &&
        obj['fmt'] === 'tpm' &&
        obj['attStmt'] &&
        obj['attStmt']['ver'] === '2.0' &&
        obj['attStmt']['alg'] &&
        obj['attStmt']['sig'] &&
        obj['attStmt']['certInfo'] &&
        obj['attStmt']['pubArea']
    )
        return true
    return false
}

export function TPMVerify(
    attestation: GenericAttestation,
    attStmt: TPMStmt,
    clientDataHash: Buffer,
    authenticatorData: AuthenticatorData
): boolean {
    // Step 1: Verify ver is "2.0"
    if (attStmt.ver !== '2.0') return false

    // Step 2: Parse certInfo and pubArea using helpers from util
    const certInfo = util.parseCertInfo(attStmt.certInfo)
    const pubArea = util.parsePubArea(attStmt.pubArea)

    // Step 3: Verify certInfo.magic is TPM_GENERATED_VALUE (0xFF544347)
    if (certInfo.magic !== 0xff544347) return false

    // Step 4: Verify certInfo.type is TPM_ST_ATTEST_CERTIFY
    if (certInfo.type !== 'TPM_ST_ATTEST_CERTIFY') return false

    // Step 5: Verify certInfo.extraData equals hash(authData || clientDataHash) using alg
    const sigHashAlg = algToHash(attStmt.alg)
    if (!sigHashAlg) {
        util.algorithmWarning(attStmt.alg)
        return false
    }
    const verificationData = Buffer.concat([attestation.authData, clientDataHash])
    const expectedExtraData = crypto
        .createHash(sigHashAlg)
        .update(verificationData)
        .digest()
    if (!expectedExtraData.equals(certInfo.extraData)) return false

    // Step 6: Verify attested.name = nameAlg(2 bytes) || hash(pubArea)
    // The first 2 bytes of attested.name encode the nameAlg used; the rest is the hash
    const nameHashAlg = tpmAlgToHash(certInfo.attested.nameAlg)
    if (!nameHashAlg) return false
    const pubAreaHash = crypto
        .createHash(nameHashAlg)
        .update(attStmt.pubArea)
        .digest()
    const nameHashBytes = certInfo.attested.name.slice(2)
    if (!pubAreaHash.equals(nameHashBytes)) return false

    if (attStmt.x5c) {
        // Step 7: Validate the AIK certificate (first cert in x5c)
        const x5cString = attStmt.x5c[0].toString('base64')
        const certPem =
            '-----BEGIN CERTIFICATE-----\n' +
            x5cString +
            '\n-----END CERTIFICATE-----'
        const cert: any = Certificate.fromPEM(Buffer.from(certPem))
        if (!validateAikCert(cert)) return false

        // Step 8: Verify sig is a valid signature over certInfo using aikCert's public key
        const cryptoAlg = algToCryptoAlg(attStmt.alg)
        if (!cryptoAlg) {
            util.algorithmWarning(attStmt.alg)
            return false
        }
        const verifier = crypto.createVerify(cryptoAlg)
        verifier.update(attStmt.certInfo)
        if (!verifier.verify(certPem, attStmt.sig)) return false
    } else if (attStmt.ecdaaKeyId) {
        util.ecdaaWarning()
        return false
    } else {
        // No x5c and no ecdaaKeyId — not a valid TPM attestation
        return false
    }

    return true
}

/**
 * Validates the AIK certificate according to the WebAuthn TPM spec requirements.
 * https://www.w3.org/TR/webauthn-2/#sctn-tpm-cert-requirements
 */
function validateAikCert(cert: x5cInterface): boolean {
    // Version MUST be 3
    if (cert.version !== 3) return false

    // Subject field MUST be empty
    if (cert.subject?.attributes?.length > 0) return false

    // Basic Constraints extension MUST have CA set to false
    const basicConstraints = cert.extensions.find(
        (ext: any) => ext.name === 'basicConstraints'
    )
    if (basicConstraints?.isCA) return false

    // Extended Key Usage MUST contain tcg-kp-AIKCertificate (OID 2.23.133.8.3)
    // DER encoding of OID 2.23.133.8.3: 06 05 67 81 05 08 03
    const ekuExtension = cert.extensions.find(
        (ext: any) => ext.oid === '2.5.29.37'
    )
    if (!ekuExtension) return false
    const aikOidBytes = Buffer.from([0x67, 0x81, 0x05, 0x08, 0x03])
    if (ekuExtension.value && ekuExtension.value.indexOf(aikOidBytes) === -1) {
        console.warn(
            'TPM AIK certificate EKU does not contain tcg-kp-AIKCertificate (2.23.133.8.3)'
        )
        return false
    }

    return true
}

/**
 * Maps a COSE algorithm identifier to the Node.js crypto hash algorithm name
 * used when hashing authData || clientDataHash for certInfo.extraData.
 */
function algToHash(alg: number): string | null {
    switch (alg) {
        case -7: // ES256
        case -37: // PS256
        case -257: // RS256
            return 'sha256'
        case -35: // ES384
        case -38: // PS384
        case -258: // RS384
            return 'sha384'
        case -36: // ES512
        case -39: // PS512
        case -259: // RS512
            return 'sha512'
        default:
            return null
    }
}

/**
 * Maps a COSE algorithm identifier to the Node.js crypto algorithm name
 * used for signature verification.
 */
function algToCryptoAlg(alg: number): string | null {
    switch (alg) {
        case -7: // ES256 — ECDSA with SHA-256
            return 'SHA256'
        case -35: // ES384 — ECDSA with SHA-384
            return 'SHA384'
        case -36: // ES512 — ECDSA with SHA-512
            return 'SHA512'
        case -257: // RS256 — RSASSA-PKCS1-v1_5 with SHA-256
            return 'RSA-SHA256'
        case -258: // RS384 — RSASSA-PKCS1-v1_5 with SHA-384
            return 'RSA-SHA384'
        case -259: // RS512 — RSASSA-PKCS1-v1_5 with SHA-512
            return 'RSA-SHA512'
        default:
            return null
    }
}

/**
 * Maps a TPM_ALG name (from parseCertInfo) to a Node.js hash algorithm name.
 * Used to verify the attested.name = nameAlg || hash(pubArea) structure.
 */
function tpmAlgToHash(nameAlg: string): string | null {
    switch (nameAlg) {
        case 'TPM_ALG_SHA':
        case 'TPM_ALG_SHA1':
            return 'sha1'
        case 'TPM_ALG_SHA256':
            return 'sha256'
        case 'TPM_ALG_SHA384':
            return 'sha384'
        case 'TPM_ALG_SHA512':
            return 'sha512'
        default:
            return null
    }
}
