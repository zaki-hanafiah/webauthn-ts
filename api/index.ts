import path from 'path'
import { router as AuthenticationRouter } from './authentication/router'

import express from 'express'
import dotenv from 'dotenv'
import cookies from 'cookie-parser'

const app = express()
dotenv.config()

app.use(cookies())
app.use(express.static(path.join(__dirname, '..', 'pages')))
app.use(
    '/.well-known',
    express.static(path.join(__dirname, '..', '.well-known'))
)

app.use('/authentication', (req, res, next) => {
    AuthenticationRouter(req, res, next)
})

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'pages', 'home.html'))
})

app.listen(process.env.PORT || 4430, () => {
    console.log('Server is running on port 4430!')
})
