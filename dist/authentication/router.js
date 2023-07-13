'use strict'
var __importDefault =
    (this && this.__importDefault) ||
    function (mod) {
        return mod && mod.__esModule ? mod : { default: mod }
    }
Object.defineProperty(exports, '__esModule', { value: true })
exports.router = void 0
const express_1 = __importDefault(require('express'))
const body_parser_1 = __importDefault(require('body-parser'))
const util_1 = require('./util')
const signup_1 = require('./signup')
const verify_1 = require('./verify')
exports.router = express_1.default.Router()
exports.router.use(body_parser_1.default.json())
exports.router.post('/register', (req, res) => {
    let msg = (0, signup_1.registerKey)(req.body.pkc, req.cookies.userId)
    res.status(msg.status).send(msg.text)
})
exports.router.post('/login', (req, res) => {
    let msg = (0, verify_1.verify)(req.body.pkc, req.cookies.userId)
    res.status(msg.status).send(msg.text)
})
exports.router.get('/creationOptions', (req, res) => {
    res.send(
        JSON.stringify((0, util_1.generatePublicKeyCredentialCreationOptions)())
    )
})
exports.router.get('/requestOptions', (req, res) => {
    res.send(
        JSON.stringify(
            (0, util_1.generatePublicKeyCredentialRequestOptions)(
                req.cookies.userId
            )
        )
    )
})
//# sourceMappingURL=router.js.map
