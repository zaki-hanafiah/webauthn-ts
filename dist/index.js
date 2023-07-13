'use strict'
var __importDefault =
    (this && this.__importDefault) ||
    function (mod) {
        return mod && mod.__esModule ? mod : { default: mod }
    }
Object.defineProperty(exports, '__esModule', { value: true })
const path_1 = __importDefault(require('path'))
const router_1 = require('./authentication/router')
const express_1 = __importDefault(require('express'))
const dotenv_1 = __importDefault(require('dotenv'))
const cookie_parser_1 = __importDefault(require('cookie-parser'))
const app = (0, express_1.default)()
dotenv_1.default.config()
app.use((0, cookie_parser_1.default)())
app.use(express_1.default.static(path_1.default.join(__dirname, '..', 'pages')))
app.use(
    '/.well-known',
    express_1.default.static(
        path_1.default.join(__dirname, '..', '.well-known')
    )
)
app.use('/authentication', (req, res, next) => {
    ;(0, router_1.router)(req, res, next)
})
app.get('/', (req, res) => {
    res.sendFile(path_1.default.join(__dirname, '..', 'pages', 'home.html'))
})
app.listen(process.env.PORT || 4430, () => {
    console.log('Server is running on port 4430!')
})
//# sourceMappingURL=index.js.map
