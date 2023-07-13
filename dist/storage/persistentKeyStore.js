'use strict'
Object.defineProperty(exports, '__esModule', { value: true })
exports.set = exports.get = void 0
let store = {}
function get(key) {
    return store[key]
}
exports.get = get
function set(key, value) {
    store[key] = value
}
exports.set = set
//# sourceMappingURL=persistentKeyStore.js.map
