'use strict'
var __createBinding =
    (this && this.__createBinding) ||
    (Object.create
        ? function (o, m, k, k2) {
              if (k2 === undefined) k2 = k
              var desc = Object.getOwnPropertyDescriptor(m, k)
              if (
                  !desc ||
                  ('get' in desc
                      ? !m.__esModule
                      : desc.writable || desc.configurable)
              ) {
                  desc = {
                      enumerable: true,
                      get: function () {
                          return m[k]
                      },
                  }
              }
              Object.defineProperty(o, k2, desc)
          }
        : function (o, m, k, k2) {
              if (k2 === undefined) k2 = k
              o[k2] = m[k]
          })
var __setModuleDefault =
    (this && this.__setModuleDefault) ||
    (Object.create
        ? function (o, v) {
              Object.defineProperty(o, 'default', {
                  enumerable: true,
                  value: v,
              })
          }
        : function (o, v) {
              o['default'] = v
          })
var __importStar =
    (this && this.__importStar) ||
    function (mod) {
        if (mod && mod.__esModule) return mod
        var result = {}
        if (mod != null)
            for (var k in mod)
                if (
                    k !== 'default' &&
                    Object.prototype.hasOwnProperty.call(mod, k)
                )
                    __createBinding(result, mod, k)
        __setModuleDefault(result, mod)
        return result
    }
var __importDefault =
    (this && this.__importDefault) ||
    function (mod) {
        return mod && mod.__esModule ? mod : { default: mod }
    }
Object.defineProperty(exports, '__esModule', { value: true })
exports.verify = void 0
const store = __importStar(require('../storage/persistentKeyStore'))
const cache = __importStar(require('../storage/challengeCache'))
const util_1 = require('./util')
const crypto_1 = __importDefault(require('crypto'))
const jwk_to_pem_1 = __importDefault(require('jwk-to-pem'))
function verify(assertion, userId) {
    let user = store.get(userId)
    if (!user) {
        return {
            status: 403,
            text: 'This user is not registered at our server!',
        }
    }
    const clientData = JSON.parse(assertion.response.clientDataJSON)
    if (clientData.type !== 'webauthn.get') {
        return {
            status: 403,
            text: 'The operation specified in the clientDataJSON is not webauthn.get',
        }
    }
    if (cache.get(clientData.challenge) === true) {
        return {
            status: 403,
            text: 'The challenge of this request has already been resolved, Hint of replay attack',
        }
    } else if (!cache.get(clientData.challenge) === false) {
        return {
            status: 403,
            text: 'The challenge of this request does not match any challenge issued',
        }
    } else cache.set(clientData.challenge, true)
    if (!/localhost/g.test(clientData.origin)) {
        if (
            process.env.BASEURL &&
            !(clientData.origin === process.env.BASEURL)
        ) {
            return {
                status: 403,
                text: 'The origin of the request does not come from the expected host server',
            }
        }
    }
    if (clientData.tokenBinding) {
    }
    let authDataBuffer = Buffer.from(
        assertion.response.authenticatorData,
        'base64'
    )
    let authenticatorData = (0, util_1.parseAuthenticatorData)(authDataBuffer)
    if (
        process.env.RPID &&
        !authenticatorData.rpIdHash.equals((0, util_1.sha256)(process.env.RPID))
    ) {
        return {
            status: 403,
            text: 'The relying party ID of the request does not match the servers RP ID',
        }
    }
    if (!(authenticatorData.flags & 1)) {
        return {
            status: 401,
            text: 'The request indicates that the user failed the presence test',
        }
    }
    if (!(authenticatorData.flags & 4)) {
        return {
            status: 401,
            text: 'The request indicates that the user did not verify before the client sent the request',
        }
    }
    if (authenticatorData.extensions && process.env.EXPTECTEDEXTENSIONS) {
        let expectedExtensions = process.env.EXPTECTEDEXTENSIONS.split(',')
        let existingExtensions = Object.keys(authenticatorData.extensions)
        for (let i = 0; i < existingExtensions.length; i++) {
            if (!expectedExtensions.includes(existingExtensions[i])) {
                return {
                    status: 403,
                    text: 'The request contains an extension that was not specified in the client-side options',
                }
            }
        }
    }
    let hash = (0, util_1.sha256)(assertion.response.clientDataJSON)
    const sig = Buffer.from(assertion.response.signature, 'base64')
    const verify =
        user.credentialPublicKey.kty === 'RSA'
            ? crypto_1.default.createVerify('RSA-SHA256')
            : crypto_1.default.createVerify('sha256')
    verify.update(authDataBuffer)
    verify.update(hash)
    if (
        !verify.verify((0, jwk_to_pem_1.default)(user.credentialPublicKey), sig)
    )
        return {
            status: 403,
            text: 'Could not verify the client signature!',
        }
    if (!(authenticatorData.signCount > user.signCount)) {
        return {
            status: 403,
            text: "The Sign-In count of the provided credential doesn't match our records!",
        }
    } else user.signCount = authenticatorData.signCount
    return { status: 200, text: 'OK' }
}
exports.verify = verify
//# sourceMappingURL=verify.js.map
