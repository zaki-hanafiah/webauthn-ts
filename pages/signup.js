// FE UI Mumbo Jumbo

function getCookie(name) {
	function escape(s) { return s.replace(/([.*+?\^$(){}|\[\]\/\\])/g, '\\$1'); }
	const match = document.cookie.match(RegExp('(?:^|;\\s*)' + escape(name) + '=([^;]*)'));
	return match ? match[1] : null;
}

function checkIfUserRegistered() {
	const userId = getCookie('userId');
	const userName = getCookie('userName');
	return !!userId && !!userName;
}

window.addEventListener('load', (event) => {
	if (checkIfUserRegistered()) {
		const userName = getCookie('userName');
		document.getElementById('login_flow').classList.remove('hidden');
		document.getElementById('register_flow').classList.add('hidden');
		document.getElementById("login_text").innerHTML = "Hi " + userName + ",";
	}
});

function validateForm() {
	if (
		document.getElementById("uname").value !== "" &&
		document.getElementById("password").value !== ""
	)
		document.getElementById("btn").removeAttribute("disabled");
	else
		document.getElementById("btn").setAttribute("disabled", "true");
}

function loadLogin() {
	document.getElementById("btn").innerHTML = "Loading...";
	document.getElementById("btn").classList.add('bg-green-600');
	window.setTimeout(() => {
		let form = document.getElementsByClassName("form")[0];
		form.innerHTML = '<div class="mb-4"><p>Your key has been successfully registered.</p><p>You are now logged in.</p></div>';
	}, 1500);
}

function disableBtn() {
	const btns = document.getElementsByTagName("button");
	Array.from(btns).forEach(btn => btn.setAttribute("disabled", "true"));
}

function verifyLogin() {
	let form = document.getElementsByClassName("form")[0];
	form.innerHTML = '<div class="mb-4"><p>You are now logged in.</p></div>';
}