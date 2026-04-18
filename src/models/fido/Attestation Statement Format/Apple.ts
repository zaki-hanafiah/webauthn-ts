import { GenericAttestation } from '../../custom/GenericAttestation'
import { AuthenticatorData } from '../AuthenticatorData'
import crypto from 'crypto'
import { Certificate } from '@fidm/x509'

/**
 * Specification: https://www.w3.org/TR/webauthn-2/#sctn-apple-anonymous-attestation
 * Used by Apple Touch ID / Face ID on macOS and iOS.
 */
export interface AppleAttestation extends GenericAttestation {
    fmt: 'apple'
    attStmt: {
        x5c: Array<Buffer>
    }
}

export function isAppleAttestation(obj: { [key: string]: any }): boolean {
    if (
        obj['fmt'] &&
        obj['fmt'] === 'apple' &&
        obj['attStmt'] &&
        Array.isArray(obj['attStmt']['x5c']) &&
        obj['attStmt']['x5c'].length > 0
    )
        return true
    return false
}

export function AppleVerify(
    attestation: GenericAttestation,
    clientDataHash: Buffer,
    authenticatorData: AuthenticatorData
): boolean {
    const attStmt = attestation.attStmt as { x5c: Array<Buffer> }

    // Build the credential certificate PEM from the first x5c entry
    const credCertPem =
        '-----BEGIN CERTIFICATE-----\n' +
        attStmt.x5c[0].toString('base64') +
        '\n-----END CERTIFICATE-----'
    const credCert: any = Certificate.fromPEM(Buffer.from(credCertPem))

    // Step 1: Compute expected nonce = SHA-256(authData || clientDataHash)
    const verificationData = Buffer.concat([attestation.authData, clientDataHash])
    const expectedNonce = crypto
        .createHash('sha256')
        .update(verificationData)
        .digest()

    // Step 2: Extract the nonce from Apple's proprietary extension (OID 1.2.840.113635.100.8.2)
    // The extension value is DER-encoded: SEQUENCE { SEQUENCE { OCTET STRING { nonce } } }
    const appleExtension = credCert.extensions.find(
        (ext: any) => ext.oid === '1.2.840.113635.100.8.2'
    )
    if (!appleExtension) return false

    const nonceFromCert = extractAppleNonce(appleExtension.value)
    if (!nonceFromCert) return false

    // Step 3: Verify that the computed nonce matches the one in the certificate
    if (!expectedNonce.equals(nonceFromCert)) return false

    // Step 4: Verify the credential public key in authData matches the cert's public key
    if (!verifyPublicKeyMatch(credCertPem, authenticatorData)) return false

    return true
}

/**
 * Extracts the nonce bytes from Apple's attestation certificate extension.
 *
 * The extension value (OID 1.2.840.113635.100.8.2) is DER-encoded as:
 *   SEQUENCE {
 *     SEQUENCE {
 *       OCTET STRING { <32-byte SHA-256 nonce> }
 *     }
 *   }
 */
function extractAppleNonce(extensionValue: Buffer): Buffer | null {
    try {
        let offset = 0

        // Outer SEQUENCE tag (0x30)
        if (extensionValue[offset++] !== 0x30) return null
        offset += derLengthBytes(extensionValue, offset)

        // Inner SEQUENCE tag (0x30)
        if (extensionValue[offset++] !== 0x30) return null
        offset += derLengthBytes(extensionValue, offset)

        // OCTET STRING tag (0x04)
        if (extensionValue[offset++] !== 0x04) return null
        const len = extensionValue[offset++]

        return extensionValue.slice(offset, offset + len)
    } catch {
        return null
    }
}

/**
 * Returns the number of bytes occupied by a DER length field starting at `offset`.
 * For lengths 0–127 this is 1 byte; for longer forms the first byte encodes how
 * many subsequent bytes carry the actual length.
 */
function derLengthBytes(buf: Buffer, offset: number): number {
    const first = buf[offset]
    if (first <= 0x7f) return 1
    return 1 + (first & 0x7f)
}

/**
 * Verifies that the credential public key stored in authenticatorData matches
 * the Subject Public Key Info in the credential certificate.
 *
 * Node.js crypto exports JWK values as base64url; coseToJwk stores them as
 * standard base64. Buffer.from(str, 'base64') accepts both variants, so we
 * compare the decoded raw bytes rather than the encoded strings.
 */
function verifyPublicKeyMatch(
    certPem: string,
    authenticatorData: AuthenticatorData
): boolean {
    try {
        const credPubKey = authenticatorData.attestedCredentialData.credentialPublicKey
        const certKey = crypto.createPublicKey(certPem)
        const certKeyJwk = certKey.export({ format: 'jwk' }) as any

        if (credPubKey.kty === 'EC') {
            if (!credPubKey.x || !credPubKey.y || !certKeyJwk.x || !certKeyJwk.y)
                return false
            return (
                certKeyJwk.kty === 'EC' &&
                Buffer.from(certKeyJwk.x as string, 'base64').equals(
                    Buffer.from(credPubKey.x, 'base64')
                ) &&
                Buffer.from(certKeyJwk.y as string, 'base64').equals(
                    Buffer.from(credPubKey.y, 'base64')
                )
            )
        } else if (credPubKey.kty === 'RSA') {
            if (!credPubKey.n || !credPubKey.e || !certKeyJwk.n || !certKeyJwk.e)
                return false
            return (
                certKeyJwk.kty === 'RSA' &&
                Buffer.from(certKeyJwk.n as string, 'base64').equals(
                    Buffer.from(credPubKey.n, 'base64')
                ) &&
                Buffer.from(certKeyJwk.e as string, 'base64').equals(
                    Buffer.from(credPubKey.e, 'base64')
                )
            )
        }

        return false
    } catch {
        return false
    }
}
