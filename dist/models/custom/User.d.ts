import { JSONWebKey } from './JSONWebKey'
export interface User {
    id: string
    signCount: number
    credentialPublicKey: JSONWebKey
}
