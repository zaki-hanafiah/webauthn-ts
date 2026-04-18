/// <reference types="node" />
/// <reference types="node" />
import { GenericAttestation } from '../../custom/GenericAttestation';
import { AuthenticatorData } from '../AuthenticatorData';
export interface TPMAttestation extends GenericAttestation {
    fmt: 'tpm';
    attStmt: TPMStmt;
}
export interface TPMStmt {
    ver: '2.0';
    alg: number;
    x5c?: Array<Buffer>;
    ecdaaKeyId?: Buffer;
    sig: Buffer;
    certInfo: Buffer;
    pubArea: Buffer;
}
export declare function isTPMAttestation(obj: {
    [key: string]: any;
}): boolean;
export declare function TPMVerify(attestation: GenericAttestation, attStmt: TPMStmt, clientDataHash: Buffer, authenticatorData: AuthenticatorData): boolean;
