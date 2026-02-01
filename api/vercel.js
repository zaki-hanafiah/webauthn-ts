const path = require('path')
const express = require('express')
const dotenv = require('dotenv')

dotenv.config()

const app = express()
const { router } = require(path.join(
    process.cwd(),
    'dist/authentication/router'
))

app.use(require('cookie-parser')())
app.use(express.static(path.join(process.cwd(), 'pages')))
app.use('/.well-known', express.static(path.join(process.cwd(), '.well-known')))
app.use('/authentication', router)

app.get('/', (req, res) => {
    res.sendFile(path.join(process.cwd(), 'pages', 'home.html'))
})

module.exports = app
