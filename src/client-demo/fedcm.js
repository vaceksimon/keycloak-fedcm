/**
 * These scripts handle logic behind signing in and out with FedCM and decoding the retrieved token.
 * @author <a href="mailto:xvacek10@stud.fit.vutbr.cz">Simon Vacek</a>
*/

/**
 * Performs a FedCM sign-in with configuration loaded from the user form. The retrieved token is stored in a cookie.
 * @see <a href="https://fedidcg.github.io/FedCM/#browser-api">FedCM API specification</a>
*/
async function login() {
    // load configuration for the login
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

	// store the token in a cookie
    const decodedToken = JSON.parse(base64UrlDecode(credential.token.split('.')[1]));
    await cookieStore.set({
        name: "accessToken",
        value: credential.token,
        expires: decodedToken.exp*1000,
        sameSite: "strict"
    });
}

/**
 * Performs a FedCM sign-out with configuration loaded from the user form. Deletes the token cookie.
 * @see <a href="https://fedidcg.github.io/FedCM/#browser-api">FedCM API specification</a>
*/
async function logout() {
    // load configuration for the logout
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

/**
 * Decodes a token into a readable form.
 * Code taken from <a href="https://github.com/PacktPublishing/Keycloak-Identity-and-Access-Management-for-Modern-Applications/blob/master/ch4/client.js">Keycloak examples from the Keycloak book</a>
 *
 * @param input Encoded token
*/
function base64UrlDecode(input) {
    input = input.replace(/-/g, '+').replace(/_/g, '/');
    var pad = input.length % 4;
    if (pad) {
        if (pad === 1) {
            throw new Error('InvalidLengthError: Input base64url string is the wrong length to determine padding');
        }
        input += new Array(5 - pad).join('=');
    }
    return atob(input);
}

/**
 * Retrieves the token from the token cookie.
 * @returns Value of the cookie or false if the cookie is not set.
*/
async function getEncodedToken() {
    const tokenCookie =  await cookieStore.get('accessToken');
    if (tokenCookie === null) {
        return false;
    }
    return tokenCookie.value;
}

/**
 * Returns a JSON representation of the body of the token.
*/
async function getJSONToken() {
    const token = await getEncodedToken();
	return token ? JSON.parse(base64UrlDecode(token.split('.')[1])) : false;
}