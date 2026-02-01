const path = require('path')

const { generatePublicKeyCredentialCreationOptions } = require(path.join(
    process.cwd(),
    'dist/authentication/util'
))

module.exports = (req, res) => {
    res.send(JSON.stringify(generatePublicKeyCredentialCreationOptions()))
}
