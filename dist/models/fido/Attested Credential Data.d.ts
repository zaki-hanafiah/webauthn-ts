/// <reference types="node" />
/// <reference types="node" />
import { JSONWebKey } from '../custom/JSONWebKey'
export interface AttestedCredentialData {
    aaguid: string
    credentialId: Buffer
    credentialIdLength: number
    credentialPublicKey: JSONWebKey
}
