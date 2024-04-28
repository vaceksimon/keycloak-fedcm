let clientId = "example-client";

async function login() {
    let nonce = 123456;
	let credential;
	try {
	    credential = await navigator.credentials.get({
	        identity: {
                providers: [{
                    configURL: "http://localhost:8080/realms/fedcm-realm/fedcm/config.json",
                    clientId: clientId,
                    nonce: nonce,
                }],
                mode: "widget"
            },
            mediation: "required",
        });
	} catch (e) {
		const code = e.code;
		const url = e.url;
		console.log(code);
		console.log(url);
		return;

	    document.getElementById('status').innerHTML="";
	    document.getElementById('message').innerHTML="";
	    document.getElementById('error').innerHTML="Error during login :(";
	}
	localStorage.setItem('accessToken', credential.token);
    document.dispatchEvent(new CustomEvent("loginStatus", {detail: "login"}))
}

async function logout() {
	try {
		await IdentityCredential.disconnect({
		    configURL: "http://localhost:8080/realms/fedcm-realm/fedcm/config.json",
		    clientId: clientId,
		    accountHint: "test@test.com",
		});
	}
	catch(e) {
		document.getElementById('error').innerHTML="Error during logout :(";
		document.getElementById('status').innerHTML="";
		document.getElementById('message').innerHTML="";
	}
	localStorage.removeItem("accessToken");
	document.dispatchEvent(new CustomEvent("loginStatus", {detail: "logout"}))
}

function base64UrlDecode(input) {
    input = input.replace(/-/g, '+').replace(/_/g, '/');
    var pad = input.length % 4;
    if (pad) {
        if (pad === 1) {
            throw new Error('InvalidLengthError: Input base64url string is the wrong length to determine padding');
        }
        input += new Array(5 - pad).join('=');
    }
    var output = atob(input);
    try {
        // Convert binary string to UTF-8
        return decodeURIComponent(Array.prototype.map.call(output, function(c) {
            return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
        }).join(''));
    } catch (e) {
        console.error(e);
        return null;
    }
}

function getJSONToken() {
    const token = localStorage.getItem('accessToken');
    if (token === null) {
        return false
    }
	return JSON.parse(base64UrlDecode(token.split('.')[1]));
}

function renderNavbar() {
    accessToken = getJSONToken();
    const loginButton = document.getElementById('loginButton');
    const profileButton = document.getElementById('profileButton');
    if (accessToken === false) {
        loginButton.innerHTML = "Login";
        loginButton.setAttribute("onclick", "login()");
        loginButton.setAttribute("class", "btn btn-outline-primary")
        profileButton.setAttribute("class", "btn btn-secondary")
    }
    else {
        loginButton.innerHTML = "Logout";
        loginButton.setAttribute("onclick", "logout()");
        loginButton.setAttribute("class", "btn btn-outline-danger")
        profileButton.setAttribute("class", "btn btn-primary")
    }
}

document.addEventListener("DOMContentLoaded", function() {
    renderNavbar();
});

document.addEventListener("loginStatus", function() {
    renderNavbar();
});

window.addEventListener("storage", function(e) {
    if(e.key === "accessToken") {
        renderNavbar();
    }
})