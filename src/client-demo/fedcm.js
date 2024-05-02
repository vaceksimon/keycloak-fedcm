clientId = "example-client";

async function login() {
    let port, mode, mediation;
    if (document.getElementById("formFedCMConfig")) {
        [port, mode, mediation] = getFedCMConfig();
    }
    else {
        port = 8080;
        mode = "widget";
        mediation = "required"
    }

    const nonce = 123456;
	let credential;
	try {
	    credential = await navigator.credentials.get({
	        identity: {
                providers: [{
                    configURL: "http://localhost:" + port + "/realms/fedcm-realm/fedcm/config.json",
                    clientId: clientId,
                    nonce: nonce,
                }],
                mode: mode,
            },
            mediation: mediation,
        })
	} catch (e) {
	    document.getElementById('alert-error').innerHTML=`
	        <div class="alert alert-danger alert-dismissible fade show">
                <a href="#" class="close" data-dismiss="alert" aria-label="close">&times;</a>
                <strong>Error during login</strong>
            </div>
	    `;
	    console.log(e);
	    return;
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
		document.getElementById('alert-error').innerHTML=`
            <div class="alert alert-danger alert-dismissible fade show">
                <a href="#" class="close" data-dismiss="alert" aria-label="close">&times;</a>
                <strong>Error during logout</strong>
            </div>
        `;
        return;
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