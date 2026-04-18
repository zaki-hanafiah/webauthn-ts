/// <reference types="node" />
/// <reference types="node" />
import { GenericAttestation } from '../../custom/GenericAttestation';
import { AuthenticatorData } from '../AuthenticatorData';
export interface AppleAttestation extends GenericAttestation {
    fmt: 'apple';
    attStmt: {
        x5c: Array<Buffer>;
    };
}
export declare function isAppleAttestation(obj: {
    [key: string]: any;
}): boolean;
export declare function AppleVerify(attestation: GenericAttestation, clientDataHash: Buffer, authenticatorData: AuthenticatorData): boolean;
