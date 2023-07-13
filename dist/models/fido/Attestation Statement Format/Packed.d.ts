/// <reference types="node" />
/// <reference types="node" />
import { GenericAttestation } from '../../custom/GenericAttestation'
import { AuthenticatorData } from '../AuthenticatorData'
export interface PackedAttestation extends GenericAttestation {
    fmt: 'packed'
    attStmt: PackedStmt
}
export interface PackedStmt {
    ver: '2.0'
    alg: number
    x5c?: Array<Buffer>
    ecdaaKeyId?: Buffer
    sig: Buffer
}
export declare function isPackedAttestation(obj: {
    [key: string]: any
}): boolean
export declare function PackedVerify(
    attestation: GenericAttestation,
    attStmt: PackedStmt,
    clientDataHash: Buffer,
    authenticatorData: AuthenticatorData
): boolean
