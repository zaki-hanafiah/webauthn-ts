import { GenericAttestation } from '../../custom/GenericAttestation'
export interface NoneAttestation extends GenericAttestation {
    fmt: 'none'
    attStmt: {}
}
export declare function isNoneAttestation(obj: { [key: string]: any }): boolean
export declare function NoneVerify(): boolean
