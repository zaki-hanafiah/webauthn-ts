# WebAuthn Typescript

### Overview

_The WebAuthn specification has two interesting parts for Web Developers:_

-   Registering a new user in your app and verifying logins of said user. In the code sample, you can find the server-side implementation of these steps in src -> authentication -> signup.ts / verify.ts.
-   All client-side (web browser) related implementation can be found in pages -> webauthn.js.
-   Click through these files and read the comments to learn about the general implementation flow.
-   If you want to dig deeper, many of the comments already have references to the part of the specification that they are implementing.

### Resources

-   [WebAuthn Guide](https://webauthn.guide/) by DUO.
-   [WebAuthn specification](https://w3c.github.io/webauthn/) in W3C.

### Demo

_The demo site for this project, can be found here_


https://webauthn-ts.vercel.app/


**Ensure you have a FIDO certified security key to test**




### Glossary:

-   [Installation](#installation)
-   [Working With This Project](#working-with-this-project)

## Installation

You will need to perform the following on your development machine:

1. Node.js (v16.4.0 is recommended) and NPM (see <https://nodejs.org/en/download/package-manager/>)
2. Clone this repo
3. Run `npm install` from the project root folder
4. Copy [.env.example](.env.example) file and rename into `.env`. Change the variables wherever necessary.
5. Run `npm run start`

## Working With This Project

|  Command   | Description                                                                                                               |
| :--------: | ------------------------------------------------------------------------------------------------------------------------- |
|  `start`   | Runs the app in the development mode. Open [http://localhost:4430](http://localhost:4430) to view it in the browser.      |
|   `css`    | Run the CLI tool to scan your template files for classes and build your CSS. Watches for any css changes if kept running. |
| `prettify` | Formatting is done on covered files based on prettier config.                                                             |
