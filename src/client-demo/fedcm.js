async function login() {
    let clientId, port, mode, mediation;
    [clientId, port, mode, mediation] = getFedCMConfig();

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
	    displayError("sign-in");
	    return;
	}
    const decodedToken = JSON.parse(base64UrlDecode(credential.token.split('.')[1]));
    await cookieStore.set({
        name: "accessToken",
        value: credential.token,
        expires: decodedToken.exp*1000,
        sameSite: "strict"
    });
}

async function logout() {
    let clientId, port;
    [clientId, port,,] = getFedCMConfig();

	try {
		await IdentityCredential.disconnect({
		    configURL: "http://localhost:" + port + "/realms/fedcm-realm/fedcm/config.json",
		    clientId: clientId,
		    accountHint: "test@test.com",
		});
	}
	catch(e) {
		displayError("sign-out");
        return;
	}
    await cookieStore.delete("accessToken")
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

async function getEncodedToken() {
    const tokenCookie =  await cookieStore.get('accessToken');
    if (tokenCookie === null) {
        return false;
    }
    return tokenCookie.value;
}

async function getJSONToken() {
    const token = await getEncodedToken();

	return token ? JSON.parse(base64UrlDecode(token.split('.')[1])) : false;
}