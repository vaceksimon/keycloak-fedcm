/**
 * These scripts handle the dynamic updating of the profile page.
 * @author <a href="mailto:xvacek10@stud.fit.vutbr.cz">Simon Vacek</a>
*/

/**
 * When change in the login status is detected, the page is rendered again to correspond to the state.
*/
async function renderProfilePage() {
    const formElement = document.getElementById("formFedCMConfig");
    const loginButton = document.getElementById("loginButton");
    const profileElement = document.getElementById('profileBody');
    const displayTokenBtn = document.getElementById('displayToken');
    const sendRequestBtn = document.getElementById('sendRequestButton');

    const accessToken = await getJSONToken();
    if(accessToken === false) {
        formElement.setAttribute("action", "javascript:login()")
        loginButton.setAttribute("class", "btn btn-outline-success")
        loginButton.innerHTML='Sign in';
        profileElement.innerHTML = 'You are not logged in';
        displayTokenBtn.setAttribute("style", "cursor:not-allowed");
        displayTokenBtn.disabled=true;
        sendRequestBtn.setAttribute("style", "cursor:not-allowed");
        sendRequestBtn.disabled=true;
        return;
    }
    formElement.setAttribute("action", "javascript:logout()")
    loginButton.setAttribute("class", "btn btn-outline-danger")
    loginButton.innerHTML='Sign out';
    displayTokenBtn.setAttribute("style", "cursor:pointer");
    displayTokenBtn.disabled=false;
    sendRequestBtn.setAttribute("style", "cursor:pointer");
    sendRequestBtn.disabled=false;

    profileElement.innerHTML =
    `
    <div class="d-flex flex-nowrap flex-column">
        <div class="row">
            <div class="col-7">
    	        <p>First name: ` + accessToken.given_name + `</p>
    		    <p>Last name: ` + accessToken.family_name + `</p>
        		<p>Email: ` + accessToken.email + `</p>
           	</div>
           	<div class="col-5">
    	        <img src="` + accessToken.picture + `" class="rounded-circle" style="aspect-ratio : 1 / 1; width: 200px;" />
    		<div class="col-7">
    	</div>
    </div>
    `
}

/**
 * Sends a request with the access token to the Keycloak OIDC userinfo endpoint and displays the response demonstrating its functionality.
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#UserInfo">UserInfo Endpoint</a>
 */
async function sendRequestWithToken() {
    // Load a proper port of Keycloak from the user form
    let port = document.getElementById('keycloakPort').value;
    if (document.getElementById('portFeedback').innerHTML !== '' || port === '') {
        port = 8080;
    }

    // prepare parameters for the request
    const token = await getEncodedToken();
    const userinfoUrl = "http://localhost:" + port + "/realms/fedcm-realm/protocol/openid-connect/userinfo";
    const headers = new Headers({'Authorization': `Bearer ${token}`});
    let response;

    try {
        // send a request to the userinfo endpoint
        response = await fetch(userinfoUrl, { method: 'GET', headers: headers });
            if(!response.ok) {
            displayError("fetching the UserInfo Keycloak endpoint");
            return;
        }
    }
    catch (e) {
        displayError("fetching the UserInfo Keycloak endpoint");
        return;
    }

    // display the JSON response in a new window
    const responseData = await response.json();
    const jsonString = JSON.stringify(responseData, null, 2);
    const blob = new Blob([jsonString], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    window.open(url, 'JSON Display', 'width=600,height=400,left=200,top=200');
}

/**
 * Displays an error at the top of the page.
 * @param message Error message
*/
function displayError(message) {
    document.getElementById('alert-error').innerHTML=`
        <div class="alert alert-danger alert-dismissible fade show">
            <a href="#" class="close" data-dismiss="alert" aria-label="close">&times;</a>
            <strong>Error during ${message}</strong>
        </div>
    `;
    return;
}

/**
 * Display the JWT of the access token in a new window
*/
async function displayToken() {
    const jsonToken = await getJSONToken();
    if(jsonToken === false) {
        return;
    }
    const jsonString = JSON.stringify(jsonToken, null, 2);
    const blob = new Blob([jsonString], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    window.open(url, 'JSON Display', 'width=600,height=400,left=200,top=200');
}

/**
 * Check if the entered port in the form is valid and display an error message if not.
 * The used regular expression is taken from <a href="https://ihateregex.io/expr/port/">iHateRegex</a>
*/
function checkPort() {
    const inputKeycloakPort = document.getElementById('keycloakPort');
    const portFeedback = document.getElementById('portFeedback');
    const regex = /^((6553[0-5])|(655[0-2][0-9])|(65[0-4][0-9]{2})|(6[0-4][0-9]{3})|([1-5][0-9]{4})|([0-5]{0,5})|([0-9]{1,4}))$/;
    if(!regex.test(inputKeycloakPort.value)) {
        inputKeycloakPort.setAttribute("class", "form-control is-invalid");
        portFeedback.innerHTML = "<span class=\"text-danger\">Invalid port entered. Default port 8080 will be used</span>";
    }
    else {
        inputKeycloakPort.setAttribute("class", "form-control");
        portFeedback.innerHTML = "";
    }
}

/**
 * Loads data from the user form and provides default values for those invalid.
*/
function getFedCMConfig() {
    let port = document.getElementById('keycloakPort').value;
    if (document.getElementById('portFeedback').innerHTML !== '' || port === '') {
        port = 8080;
    }
    let clientId = document.getElementById('clientID').value;
    if(clientId === '') {
        clientId = "example-client";
    }

    const mode = document.querySelector('input[name = "mode"]:checked').value;
    const mediation = document.querySelector('input[name = "mediation"]:checked').value;
    return [clientId, port, mode, mediation];
}

// Registering check function for the port input in the form
document.addEventListener("DOMContentLoaded", () => {
    renderProfilePage();
    document.getElementById('keycloakPort').addEventListener('keyup', checkPort);
    document.getElementById('keycloakPort').addEventListener('mouseup', checkPort);
});

// Registering a new render of the page if token cookie was changed or deleted
cookieStore.addEventListener("change", function(e) {
    for(cookie of e.changed) {
        if(cookie.name === "accessToken") {
            renderProfilePage();
        }
    }
    for(cookie of e.deleted) {
        if(cookie.name === "accessToken") {
            renderProfilePage();
        }
    }
});
