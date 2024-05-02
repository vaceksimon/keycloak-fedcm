async function renderProfilePage() {
    const profileElement = document.getElementById('profileBody');
    const displayTokenElement = document.getElementById('displayToken');
    const loginButton = document.getElementById("loginButton");
    const formElement = document.getElementById("formFedCMConfig");

    const accessToken = await getJSONToken();
    if(accessToken === false) {
        profileElement.innerHTML = 'You are not logged in';
        displayTokenElement.setAttribute("style", "cursor:not-allowed");
        displayTokenElement.disabled=true;
        formElement.setAttribute("action", "javascript:login()")
        loginButton.setAttribute("class", "btn btn-outline-success")
        loginButton.innerHTML='Sign in';
        return;
    }
    displayTokenElement.setAttribute("style", "cursor:pointer");
    displayTokenElement.disabled=false;
    formElement.setAttribute("action", "javascript:logout()")
    loginButton.setAttribute("class", "btn btn-outline-danger")
    loginButton.innerHTML='Sign out';

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
