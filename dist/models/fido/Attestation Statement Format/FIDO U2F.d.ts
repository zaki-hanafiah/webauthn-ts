/// <reference types="node" />
/// <reference types="node" />
import { GenericAttestation } from '../../custom/GenericAttestation';
export interface FIDOU2FAttestation extends GenericAttestation {
    fmt: 'fido-u2f';
    attStmt: {
        x5c: Array<Buffer>;
        sig: Buffer;
    };
}
export declare function isFIDOU2FAttestation(obj: {
    [key: string]: any;
}): boolean;
export declare function FIDOU2FVerify(attestation: GenericAttestation, clientDataHash: Buffer): boolean;
