const path = require('path')

module.exports = (req, res) => {
    try {
        const {
            generatePublicKeyCredentialCreationOptions,
        } = require(path.join(process.cwd(), 'dist/authentication/util'))
        const result = generatePublicKeyCredentialCreationOptions()
        res.send(JSON.stringify(result))
    } catch (error) {
        res.status(500).send('Error: ' + error.message + '\n' + error.stack)
    }
}
