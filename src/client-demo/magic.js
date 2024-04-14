async function login() {
    let nonce = 123456;
	let credential;
	try {
	    credential = await navigator.credentials.get({
	        identity: {
				context: "signup",
                providers: [{
                    configURL: "http://localhost:8080/realms/fedcm-realm/fedcm/config.json",
                    clientId: "example-idtoken",
                    nonce: nonce,
                }],
                mode: "widget"
            },
            mediation: "optional",
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
	decodedToken = getJSONIdToken(credential);
	
	document.getElementById('status').innerHTML="Token: " + JSON.stringify(decodedToken);
	document.getElementById('message').innerHTML="Hello " + decodedToken.given_name + " " + decodedToken.family_name + ". I have stolen your identity :)";
	    document.getElementById('error').innerHTML="";
}

async function logout() {
	try {
		await IdentityCredential.disconnect({
		    configURL: "http://localhost:8080/realms/fedcm-realm/fedcm/config.json",
		    clientId: "example-idtoken",
		    accountHint: "test@test.com"
		});

	    document.getElementById('status').innerHTML="Logout was successful";
	    document.getElementById('message').innerHTML="";
		document.getElementById('error').innerHTML="";
	}
	catch(e) {
		document.getElementById('error').innerHTML="Error during logout :(";
		document.getElementById('status').innerHTML="";
		document.getElementById('message').innerHTML="";
	}
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

function getJSONIdToken(credential) {
	return JSON.parse(base64UrlDecode(credential.token.split('.')[1]));
}
