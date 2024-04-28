function renderProfilePage() {
    renderNavbar();
    accessToken = localStorage.getItem('accessToken');
    const profileElement = document.getElementById('profileBody');
    const displayTokenElement = document.getElementById('displayToken');

    if(accessToken === null) {
        profileElement.innerHTML = 'You are not logged in';
        displayTokenElement.setAttribute("style", "cursor:not-allowed");
        displayTokenElement.disabled=true;
        return;
    }
    displayTokenElement.setAttribute("style", "cursor:pointer");
    displayTokenElement.disabled=false;

    decodedToken = getJSONToken(accessToken);

    profileElement.innerHTML =
    `
    <div class="d-flex flex-nowrap flex-column">
        <div class="row">
            <div class="col-7">
    	        <p>First name: ` + decodedToken.given_name + `</p>
    		    <p>Last name: ` + decodedToken.family_name + `</p>
        		<p>Email: ` + decodedToken.email + `</p>
           	</div>
           	<div class="col-5">
    	        <img src="` + decodedToken.picture + `" class="rounded-circle" style="aspect-ratio : 1 / 1; width: 200px;" />
    		<div class="col-7">
    	</div>
    </div>
    `
}

function displayToken() {
    const jsonToken = getJSONToken();
    if(jsonToken === false) {
        return;
    }
    const jsonString = JSON.stringify(jsonToken, null, 2);
    const blob = new Blob([jsonString], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    window.open(url, 'JSON Display', 'width=600,height=400,left=200,top=200');

}

document.addEventListener("DOMContentLoaded", () => {
    renderProfilePage();
    document.getElementById('keycloakPort').addEventListener('keyup', checkPort);
    document.getElementById('keycloakPort').addEventListener('mouseup', checkPort);
});

document.addEventListener("loginStatus", () => {
    renderProfilePage();
});

window.addEventListener("storage", function(e) {
    if(e.key === "accessToken") {
        renderProfilePage();
    }
})

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
