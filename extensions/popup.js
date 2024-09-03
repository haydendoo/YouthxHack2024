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
        text['red'] = message.text;
        hideDesc("green");
        hideDesc("yellow");
        showDesc("red");
    }
    else if(message.action === "yellowAlert") {
        text['yellow'] = message.text;
        hideDesc("green");
        hideDesc("red");
        showDesc("yellow");
    }
});