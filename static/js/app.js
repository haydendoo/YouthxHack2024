function canScan() {
    const url = document.getElementById('url').value.trim();
    const fileInput = document.getElementById('qr').files.length > 0;
    document.getElementById('scan').disabled = !(url || fileInput);
}

function scanQRCode() {
    const fileInput = document.getElementById('qr').files[0];
    if (!fileInput) {
        document.getElementById('result').innerText = 'No file uploaded.';
        return;
    }

    const reader = new FileReader();
    reader.onload = function (e) {
        const imgElement = document.createElement('img');
        imgElement.src = e.target.result;
        imgElement.onload = function () {
            const canvas = document.createElement('canvas');
            const context = canvas.getContext('2d');
            canvas.width = imgElement.width;
            canvas.height = imgElement.height;
            context.drawImage(imgElement, 0, 0, canvas.width, canvas.height);

            const imageData = context.getImageData(0, 0, canvas.width, canvas.height);
            const code = jsQR(imageData.data, canvas.width, canvas.height, {
                inversionAttempts: "dontInvert",
            });

            if (code) {
                document.getElementById('result').innerText = `${code.data}`;
            } else {
                document.getElementById('result').innerText = 'No QR Code found';
            }
        };
    };
    reader.readAsDataURL(fileInput);
}

function canScan1() {
    const urlInput = document.getElementById('phishing');
    const submitButton = document.getElementById('scan1');
    if (urlInput.value !== '') {
        submitButton.disabled = false;
    } else {
        submitButton.disabled = true;
    }
}

document.getElementById("emailsmsScanner").addEventListener("submit", async (ev) => {
    ev.preventDefault();

    const msg = document.getElementById("phishing").value;
    let res = await fetch("/verify/emailsms", {
        method: "POST",
        headers: {
            "Content-Type": "text/plain"
        },
        body: msg
    });
    res = await res.json();
    let ans = document.getElementById("phishScanMsg");
    if(res['phish'] === "True") {
        ans.innerText = "This message is likely phishing you! Beaware of clicking any links.";
        ans.style.color = "red";
    }
    else {
        ans.innerText = "This message is most likely safe.";
        ans.style.color = "green";
    }
});