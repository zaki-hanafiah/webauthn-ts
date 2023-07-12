import { GenericAttestation } from '../../custom/GenericAttestation'

/**
 * Specification: https://w3c.github.io/webauthn/#sctn-fido-u2f-attestation
 */
export interface FIDOU2FAttestation extends GenericAttestation {
    fmt: 'fido-u2f'
    attStmt: {
        x5c: Array<Buffer>
        sig: Buffer
    }
}

export function isFIDOU2FAttestation(obj: { [key: string]: any }): boolean {
    if (
        obj['fmt'] &&
        obj['fmt'] === 'fido-u2f' &&
        obj['attStmt'] &&
        obj['attStmt']['x5c'] &&
        obj['attStmt']['sig']
    )
        return true
    return false
}

export function FIDOU2FVerify(
    attestation: GenericAttestation,
    clientDataHash: Buffer
): boolean {
    //TODO
    return true
}
