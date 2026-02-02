/// <reference types="node" />
/// <reference types="node" />
import { AttestedCredentialData } from './Attested Credential Data';
export interface AuthenticatorData {
    flags: number;
    attestedCredentialData: AttestedCredentialData;
    extensions?: {
        [key: string]: any;
    };
    rpIdHash: Buffer;
    signCount: number;
}
