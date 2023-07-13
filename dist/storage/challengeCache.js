'use strict'
Object.defineProperty(exports, '__esModule', { value: true })
exports.set = exports.get = void 0
let cache = {}
function get(key) {
    return cache[key]
}
exports.get = get
function set(key, value) {
    cache[key] = value
}
exports.set = set
//# sourceMappingURL=challengeCache.js.map
