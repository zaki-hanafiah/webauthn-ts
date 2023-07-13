'use strict'
Object.defineProperty(exports, '__esModule', { value: true })
exports.NoneVerify = exports.isNoneAttestation = void 0
function isNoneAttestation(obj) {
    if (obj['fmt'] && obj['fmt'] === 'none' && obj['attStmt']) return true
    return false
}
exports.isNoneAttestation = isNoneAttestation
function NoneVerify() {
    return true
}
exports.NoneVerify = NoneVerify
//# sourceMappingURL=None.js.map
