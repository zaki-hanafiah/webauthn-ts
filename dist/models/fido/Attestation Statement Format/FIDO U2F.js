'use strict'
Object.defineProperty(exports, '__esModule', { value: true })
exports.FIDOU2FVerify = exports.isFIDOU2FAttestation = void 0
function isFIDOU2FAttestation(obj) {
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
exports.isFIDOU2FAttestation = isFIDOU2FAttestation
function FIDOU2FVerify(attestation, clientDataHash) {
    return true
}
exports.FIDOU2FVerify = FIDOU2FVerify
//# sourceMappingURL=FIDO%20U2F.js.map
