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
Object.defineProperty(exports, '__esModule', { value: true })
exports.registerKey = void 0
const util_1 = require('./util')
const storage = __importStar(require('../storage/persistentKeyStore'))
const cache = __importStar(require('../storage/challengeCache'))
const Packed_1 = require('../models/fido/Attestation Statement Format/Packed')
const FIDO_U2F_1 = require('../models/fido/Attestation Statement Format/FIDO U2F')
const None_1 = require('../models/fido/Attestation Statement Format/None')
const CBOR = __importStar(require('cbor'))
function registerKey(keyCredentialObject, userId) {
    const clientData = JSON.parse(keyCredentialObject.clientDataJSON)
    if (!(clientData.type === 'webauthn.create')) {
        return {
            status: 403,
            text: 'The operation specified in the clientDataJSON is not webauthn.create',
        }
    }
    if (cache.get(clientData.challenge) === true) {
        return {
            status: 403,
            text: 'The challenge of this request has already been resolved, Hint of replay attack',
        }
    } else if (!!cache.get(clientData.challenge)) {
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
                text:
                    'The origin of the request (' +
                    clientData.origin +
                    ') does not come from the expected host server',
            }
        }
    }
    if (clientData.tokenBinding) {
    }
    const clientDataHash = (0, util_1.sha256)(JSON.stringify(clientData))
    const attestation = CBOR.decodeFirstSync(
        Buffer.from(keyCredentialObject.attestationObject, 'base64')
    )
    const authenticatorData = (0, util_1.parseAuthenticatorData)(
        attestation.authData
    )
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
            status: 403,
            text: 'The request indicates that the user failed the presence test',
        }
    }
    if (!(authenticatorData.flags & 4)) {
        return {
            status: 403,
            text: 'The request indicates that the user did not verify before the client sent the request',
        }
    }
    if (
        process.env.ALLOWEDALGORITHMS &&
        !process.env.ALLOWEDALGORITHMS.split(',').includes(
            authenticatorData.attestedCredentialData.credentialPublicKey.kty
        )
    ) {
        return {
            status: 403,
            text: 'The request used an encryption method that is not allowed by this server',
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
    if (
        !(
            (0, Packed_1.isPackedAttestation)(attestation) ||
            (0, FIDO_U2F_1.isFIDOU2FAttestation)(attestation) ||
            (0, None_1.isNoneAttestation)(attestation)
        )
    ) {
        return {
            status: 403,
            text: "The request doesn't match any known attestation type and can therefore not be processed",
        }
    }
    let validAttestationSignature = false
    switch (attestation.fmt) {
        case 'packed':
            validAttestationSignature = (0, Packed_1.PackedVerify)(
                attestation,
                attestation.attStmt,
                clientDataHash,
                authenticatorData
            )
            break
        case 'fido-u2f':
            validAttestationSignature = (0, FIDO_U2F_1.FIDOU2FVerify)(
                attestation,
                clientDataHash
            )
            break
        case 'none':
            validAttestationSignature = (0, None_1.NoneVerify)()
            break
        default:
            break
    }
    if (!validAttestationSignature) {
        return {
            status: 403,
            text: 'The requests attestation signature could not be verified',
        }
    }
    let potentialUser = storage.get(userId)
    if (potentialUser && potentialUser.id === keyCredentialObject.id) {
        return {
            status: 401,
            text: 'The credentialId is already in use. Please re-attempt the registration',
        }
    }
    const credential = {
        id: keyCredentialObject.id,
        credentialPublicKey:
            authenticatorData.attestedCredentialData.credentialPublicKey,
        signCount: authenticatorData.signCount,
    }
    storage.set(userId, credential)
    return { status: 200, text: 'Registration successful!' }
}
exports.registerKey = registerKey
//# sourceMappingURL=signup.js.map
