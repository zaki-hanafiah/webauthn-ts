// FE UI Mumbo Jumbo
let current_flow = 'register'

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
	document.getElementById("btn").classList.add('bg-green-600')
	window.setTimeout(() => {
		let form = document.getElementsByClassName("form")[0];
		form.innerHTML = '<div class="mb-4"><p>Your key has been successfully registered.</p><p>You are now logged in.</p></div>';

	}, 1500)
}

function disableBtn() {
	const btns = document.getElementsByTagName("button");
	Array.from(btns).forEach(btn => btn.setAttribute("disabled", "true"));
}

function verifyLogin() {
	let form = document.getElementsByClassName("form")[0];
	form.innerHTML = '<div class="mb-4"><p>You are now logged in.</p></div>';
}