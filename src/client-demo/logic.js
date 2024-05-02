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
//http://localhost:8080/realms/fedcm-realm/protocol/openid-connect/userinfo
async function sendRequestWithToken() {
    let port = document.getElementById('keycloakPort').value;
    if (document.getElementById('portFeedback').innerHTML !== '' || port === '') {
        port = 8080;
    }

    const token = await getEncodedToken();
    const userinfoUrl = "http://localhost:" + port + "/realms/fedcm-realm/protocol/openid-connect/userinfo";
    const headers = new Headers({'Authorization': `Bearer ${token}`});
    let response;

    try {
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

    const responseData = await response.json();
    const jsonString = JSON.stringify(responseData, null, 2);
    const blob = new Blob([jsonString], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    window.open(url, 'JSON Display', 'width=600,height=400,left=200,top=200');
}

function displayError(message) {
    document.getElementById('alert-error').innerHTML=`
        <div class="alert alert-danger alert-dismissible fade show">
            <a href="#" class="close" data-dismiss="alert" aria-label="close">&times;</a>
            <strong>Error during ${message}</strong>
        </div>
    `;
    return;
}


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

function checkPort() {
    const inputKeycloakPort = document.getElementById('keycloakPort');
    const portFeedback = document.getElementById('portFeedback');
    const regex = /^((6553[0-5])|(655[0-2][0-9])|(65[0-4][0-9]{2})|(6[0-4][0-9]{3})|([1-5][0-9]{4})|([0-5]{0,5})|([0-9]{1,4}))$/; // https://ihateregex.io/expr/port/
    if(!regex.test(inputKeycloakPort.value)) {
        inputKeycloakPort.setAttribute("class", "form-control is-invalid");
        portFeedback.innerHTML = "<span class=\"text-danger\">Invalid port entered. Default port 8080 will be used</span>";
    }
    else {
        inputKeycloakPort.setAttribute("class", "form-control");
        portFeedback.innerHTML = "";
    }
}


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

document.addEventListener("DOMContentLoaded", () => {
    renderProfilePage();
    document.getElementById('keycloakPort').addEventListener('keyup', checkPort);
    document.getElementById('keycloakPort').addEventListener('mouseup', checkPort);
});

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
