function hideDesc(color) {
    const colorDesc = document.getElementById(color + 'Desc');
    const descTriangle = document.getElementById(color + 'Triangle');
    colorDesc.style.display = 'none';
    descTriangle.style.display = 'none';
}

let text = {
    "green": "Nothing malicious was detected",
    "red": "",
    "yellow": ""
};

function showDesc(color) {
    const colorDesc = document.getElementById(color + 'Desc');
    const descTriangle = document.getElementById(color + 'Triangle');
    colorDesc.style.display = 'block';
    colorDesc.innerText = text[color];
    descTriangle.style.display = 'block';
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === 'redAlert') {
        hideDesc("green");
        hideDesc("yellow");
        showDesc("red");
        text['red'] = message.text;
    }
    else if(message.action === "yellowAlert") {
        hideDesc("green");
        hideDesc("red");
        showDesc("yellow");
        text['yellow'] = message.text;
    }
});