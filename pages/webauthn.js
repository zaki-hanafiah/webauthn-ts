let printed_data = {};

// This function starts the registration of a new Credential at the users' client.
// It completes steps 1 + 2 of the specification before sending all data to the server for further processing.
// The specification can be found here: https://w3c.github.io/webauthn/#sctn-registering-a-new-credential
async function register(userId, userName, pin) {
	try {
		// To create a new credential that is conformed with the WebAuthn standard, we have to provide some options.
		// A complete overview over all options can be found here: https://w3c.github.io/webauthn/#dictionary-makecredentialoptions
		// response in session/new --> registerRequest
		const publicKeyCredentialCreationOptions = await getServerSideCreationOptions();

		const el_json_print = document.getElementById('jsonPrint');
		Object.assign(printed_data, { '/session/new': {
			payload: { userName: userName, pin: pin },
			response: {
				userName: userName,
				pin: pin,
				registerRequest: publicKeyCredentialCreationOptions
			}
		}});
		if (el_json_print) {
			el_json_print.classList.add('border');
			el_json_print.classList.add('border-2');
			el_json_print.classList.add('rounded');
			el_json_print.classList.add('border-grey-100');
			el_json_print.classList.add('p-4');
			el_json_print.innerHTML = prettyPrintJson.toHtml(printed_data);
		}

		publicKeyCredentialCreationOptions.challenge = Uint8Array.from(
			publicKeyCredentialCreationOptions.challenge, c => c.charCodeAt(0)).buffer;
		publicKeyCredentialCreationOptions.user.id = Uint8Array.from(
			userId, c => c.charCodeAt(0));
		publicKeyCredentialCreationOptions.user.name = userName;
		publicKeyCredentialCreationOptions.user.displayName = userName;
		publicKeyCredentialCreationOptions.authenticatorSelection.authenticatorAttachment = "cross-platform";
		publicKeyCredentialCreationOptions.authenticatorSelection.userVerification = "required";

		//Here a new credential is created which means the client verifies the user (e.g. through YubiKey) and asks for consent to store a new login credential for this website.
		// If the user agrees, a new credentialObject is scheduled.
		const credential = await navigator.credentials.create({
			publicKey: publicKeyCredentialCreationOptions
		});

		// Response from navigator.credentials.create will be used for attestation below
		let rawId = new Uint8Array(credential.rawId);

		//The credential object is secured by the client and can for example not be sent directly to the server.
		// Therefore, we extract all relevant information from the object, transform it to a securely encoded and server-interpretable format and then send it to our server for further verification.
		let attestation = {
			id: bufferEncode(rawId),
			readableId: credential.id,
			clientDataJSON: arrayBufferToString(credential.response.clientDataJSON),
			attestationObject: base64encode(credential.response.attestationObject)
		};

		fetch("/authentication/register", {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json'
			},
			redirect: 'follow',
			referrer: 'no-referrer',
			body: JSON.stringify({
				pkc: attestation
			})
		}).then(resp => {
			console.log(resp);
			if (resp.status === 200) {
				document.cookie = "userName=" + userName;
				loadLogin();
			}
			else {
				resp.text().then((t) => {
					console.error(resp.status + " " + t);
				})
			}
			Object.assign(printed_data, { '/session/webauthn/device': {
				payload: { pkc: attestation },
				response: { status: resp.status, ok: resp.ok }},
			});
			if (el_json_print) {
				el_json_print.innerHTML = prettyPrintJson.toHtml(printed_data);
			}
		})
	}
	catch (e) {
		document.getElementById("error").innerHTML = e;
	}

}

// This function triggers the verification of a user who already has a credential for this website stored on the client.
// Steps 1 - 3 as well as 5 - 6 of the specified verification process are already completed at the client, all further validation takes place at the webserver.
// You can find the full specification here: https://w3c.github.io/webauthn/#sctn-verifying-assertion
async function login(userId, userName) {
	try {
		// To create a new credential that is conformed with the WebAuthn standard, we have to provide some options.
		// A complete overview over all options can be found here: https://w3c.github.io/webauthn/#dictionary-assertion-options
		const publicKeyCredentialRequestOptions = await getServerSideRequestOptions();

		publicKeyCredentialRequestOptions.challenge = Uint8Array.from(
			publicKeyCredentialRequestOptions.challenge, c => c.charCodeAt(0)).buffer;
		publicKeyCredentialRequestOptions.allowCredentials[0].id = bufferDecode(publicKeyCredentialRequestOptions.allowCredentials[0].id);
		publicKeyCredentialRequestOptions.userVerification = "required";

		const el_json_print = document.getElementById('jsonPrint');
		Object.assign(printed_data, { '/session/new': {
				payload: { username: userName },
				response: {
					userName: userName,
					userId: userId,
					signRequest: publicKeyCredentialRequestOptions
				}
			}});
		if (el_json_print) {
			el_json_print.classList.add('border');
			el_json_print.classList.add('border-2');
			el_json_print.classList.add('rounded');
			el_json_print.classList.add('border-grey-100');
			el_json_print.classList.add('p-4');
			el_json_print.innerHTML = prettyPrintJson.toHtml(printed_data);
		}

		// Here the user is prompted to verify. If the verification succeeds, the client returns an object with all relevant credentials of the user.
		const assertion = await navigator.credentials.get({
			publicKey: publicKeyCredentialRequestOptions
		});

		// The credential object is secured by the client and can for example not be sent directly to the server.
		// Therefore, we extract all relevant information from the object, transform it to a securely encoded and server-interpretable format and then send it to our server for further verification.
		const readableAssertion = {
			id: base64encode(assertion.rawId),
			rawId: base64encode(assertion.rawId),
			response: {
				clientDataJSON: arrayBufferToString(assertion.response.clientDataJSON),
				authenticatorData: base64encode(assertion.response.authenticatorData),
				signature: base64encode(assertion.response.signature),
				userHandle: base64encode(assertion.response.userHandle),
			}

		};

		fetch("/authentication/login", {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json'
			},
			redirect: 'follow',
			referrer: 'no-referrer',
			body: JSON.stringify({
				pkc: readableAssertion
			})
		}).then(resp => {
			if (resp.status === 200) {
				verifyLogin();
			}
			else {
				resp.text().then((t) => {
					console.error(resp.status + " " + t);
				})
			}
			Object.assign(printed_data, { '/session/webauth/new': {
					payload: { pkc: readableAssertion },
					response: { status: resp.status, ok: resp.ok }},
			});
			if (el_json_print) {
				el_json_print.innerHTML = prettyPrintJson.toHtml(printed_data);
			}
		})
	}
	catch (e) {
		document.getElementById("error").innerHTML = e;
	}

}

/* --- HELPER FUNCTIONS --- */


/*
When we create a new Public Key for the WebAuthn protocol, we have to provide a challenge which is a random String that our server schedules.
This way, when we receive the public key on our server, we can correlate that key with the challenge and mark the challenge as fulfilled.
By that, we can mitigate replay attacks as every challenge can only be used once to create a public key.
For more details, see https://w3c.github.io/webauthn/#sctn-cryptographic-challenges
*/
async function getServerSideCreationOptions() {
	let resp = await fetch("/authentication/creationOptions");
	return await resp.json();
}

async function getServerSideRequestOptions() {
	let resp = await fetch("/authentication/requestOptions");
	return await resp.json();
}

//Function that encodes a UInt8Array to a base64 encoded string
function base64encode(arrayBuffer) {
	if (!arrayBuffer || arrayBuffer.length === 0)
		return undefined;

	return btoa(String.fromCharCode.apply(null, new Uint8Array(arrayBuffer)));
}

//Function that converts an ArrayBuffer to a string
function arrayBufferToString(arrayBuffer) {
	return String.fromCharCode.apply(null, new Uint8Array(arrayBuffer));
}

//Gathers all necessary parameters for register() and sets a user cookie to assign user an ID for their "account".
// This ID is only used at the client-side and is only required to tell the browser with which account the user should be verified (logged in).
function startRegistration() {
	let uid = generateId();
	document.cookie = "userId=" + uid;
	let uname = document.getElementById("uname").value;
	let pin = document.getElementById("password").value;
	if (uname && uid) {
		disableBtn();
		register(uid, uname, pin);
	}
	else console.error("Parameters missing!");
}

function getCookie(name) {
	function escape(s) { return s.replace(/([.*+?\^$(){}|\[\]\/\\])/g, '\\$1'); }
	const match = document.cookie.match(RegExp('(?:^|;\\s*)' + escape(name) + '=([^;]*)'));
	return match ? match[1] : null;
}

function doLogin() {
	disableBtn();
	const userName = getCookie('userName');
	const userId = getCookie('userId');
	login(userId, userName);
}

function generateId() {
	let charPool = "1234567890qwertzuiopasdfghjklyxcvbnm";
	let rString = "";
	for (let i = 0; i < 32; i++) {
		rString += charPool.charAt(Math.floor(Math.random() * charPool.length));
		if (i % 8 === 0 && i > 0) rString += "-";
	}
	return rString;
}

//Function that correctly encodes the rawId of the credentials object into a string that should match credential.Id
function bufferEncode(value) {
	return base64js.fromByteArray(value)
		.replace(/\+/g, "-")
		.replace(/\//g, "_")
		.replace(/=/g, "");
}

//Function to correctly decode credential.Id
function bufferDecode(value) {
	value = value
		.replace(/\-/g, "+")
		.replace(/\_/g, "/");
	return Uint8Array.from(atob(value), c => c.charCodeAt(0));
}