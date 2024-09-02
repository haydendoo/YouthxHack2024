// Fetch malicious db
let badDomains = []
fetch(chrome.runtime.getURL('malicious_db.txt'))
.then(response => response.text())
.then(text => {
    badDomains = text.split("\n");
})
.catch(error => console.error('Error loading malicious db:', error));

class SecurityCheck {
    constructor(name, desc, severity, checkFunction) {
        this.name = name;
        this.desc = desc;
        this.severity = severity; // 0 is yellow, 1 is red
        this.checkFunction = checkFunction;
    }

    check(info) {
        return this.checkFunction(info);
    }
}

const SIZE_THRESHOLD = 5e8;

const requestSecurityChecks = [
    new SecurityCheck(
        "HTTPS Check",
        "This checks if traffic is encrypted with HTTPS. Beaware of using HTTP as it may reveal sensitive information.",
        0,
        (req) => {
            return req.url.startsWith('https://') || req.url.startsWith("chrome-extension://");
        }
    ),
    new SecurityCheck(
        "Domain Check",
        "This checks if the domain is in the database of known malicious domains",
        1,
        (req) => {
            const url = new URL(req.url);
            return !badDomains.includes(url.hostname);
        }
    ),
    new SecurityCheck(
        "Payload Size Check",
        "This checks if the payload size is unusually large which may indicate an attack",
        0,
        (req) => {
            const rawData = req.requestBody.raw;
            let totalSize = 0;

            if (rawData) {
                rawData.forEach((element) => {
                    totalSize += element.bytes.byteLength;
                });
            }
            
            return totalSize < SIZE_THRESHOLD;
        }
    ),
    new SecurityCheck(
        "Port Check",
        "This checks if the request is sent to a non standard port which may indicate an attack",
        0,
        (req) => {
            try {
                const url = new URL(req.url); 
                const port = url.port || (url.protocol === 'http:' ? '80' : '443');
                return port === '80' || port === '443';
            } catch (error) {
                console.error("Error parsing URL:", error);
                // Let it pass by default
                return true;
            }
        }
    ),
    new SecurityCheck(
        "IP Check",
        "This checks if the request is sent to an IP address or to a domain",
        1,
        (req) => {
            try {
                const url = new URL(req.url); 
                const ipRegex = /^\d{1,3}(\.\d{1,3}){3}$/;
                return ipRegex.test(url.hostname);
            } catch (error) {
                console.error("Error parsing URL:", error);
                // Let it pass by default
                return true;
            }
        }
    ),
    new SecurityCheck(
        "CSRF Check",
        "This checks for potential CSRF attacks",
        0,
        (req) => {
            const requestHeaders = req.requestHeaders || [];

            const refererHeader = requestHeaders.find(header => header.name.toLowerCase() === "referer");
            if(!refererHeader) return false;

            const originHeader = requestHeaders.find(header => header.name.toLowerCase() === "origin");
            if(!originHeader) return false;

            const csrfTokenHeader = requestHeaders.find(header => header.name.toLowerCase() === "x-csrf-token");
            if(!csrfTokenHeader) return false;

            return true;
        }
    )
];

const responseSecurityChecks = [
    new SecurityCheck(
        "Payload Size Check",
        "This checks if the payload size is unusually large which may indicate an attack",
        0,
        (res) => {
            const contentLengthHeader = res.responseHeaders.find(header => header.name.toLowerCase() === "content-length");
            if(contentLengthHeader) {
                const contentLength = parseInt(contentLengthHeader.value, 10);
                return contentLength < SIZE_THRESHOLD;
            }
            return true;
        }
    ),
    new SecurityCheck(
        "CSP Check",
        "This checks for weak CSP",
        0,
        (res) => {
            // Check for CSP headers
            const cspHeader = res.responseHeaders.find(header => 
                header.name.toLowerCase() === "content-security-policy"
            );

            if(cspHeader) {
                if(cspHeader.value.includes("default-src *")) return false;
                if(cspHeader.value.includes("'unsafe-inline'")) return false;
                if(cspHeader.value.includes("'unsafe-eval'")) return false;
            }

            return true;
        }
    )
];

let pendingRequest = null, allowedRequest = null;

function interceptReq(req) {
    if(allowedRequest !== null && req.url === allowedRequest.url && req.method === allowedRequest.method && req.requestHeaders === allowedRequest.requestHeaders && req.requestBody === allowedRequest.requestBody) {
        allowedRequest = null;
        return { cancel: false };
    }
    for(let i = 0; i < requestSecurityChecks.length; ++i) {
        if(requestSecurityChecks[i].check(req)) continue;

        pendingRequest = req; 
        chrome.notifications.create({
            type: 'basic',
            iconUrl: 'logo.png',
            title: `Security Alert. Failed ${ requestSecurityChecks[i].name }`,
            message: `Suspicious request blocked: ${req.url}\n${requestSecurityChecks[i].desc}\nIf you think this is an error, disable PhishNet temporarily.`,
            buttons: [{ title: 'Allow Anyway' }]
        });

        chrome.runtime.sendMessage({
            action: requestSecurityChecks[i].severity === 0 ? 'yellowAlert' : 'redAlert',
            text: `Suspicious request blocked: ${req.url}\n${requestSecurityChecks[i].desc}\nIf you think this is an error, disable PhishNet temporarily.`,
        });

        return { cancel: true };
    }
    return { cancel: false };
}

function interceptRes(res) {
    for(let i = 0; i < responseSecurityChecks.length; ++i) {
        if(responseSecurityChecks[i].check(res)) continue;

        chrome.notifications.create({
            type: 'basic',
            iconUrl: 'logo.png',
            title: `Security Alert. Failed ${responseSecurityChecks[i].name}`,
            message: `Suspicious response blocked: ${res.url}.\n${responseSecurityChecks[i].desc}\nIf you think this an error, disable PhishNet temporarily.`,
        });

        chrome.runtime.sendMessage({
            action: responseSecurityChecks[i].severity === 0 ? 'yellowAlert' : 'redAlert',
            text: `Suspicious request blocked: ${req.url}\n${responseSecurityChecks[i].desc}\nIf you think this is an error, disable PhishNet temporarily.`,
        });

        return { cancel: true };
    }
    return { cancel: false };
}

chrome.webRequest.onBeforeRequest.addListener(interceptReq, {
    urls: ["<all_urls>"],
}, ["blocking"]);

chrome.webRequest.onHeadersReceived.addListener(interceptRes, {
    urls: ["<all_urls>"],
}, ["blocking", "responseHeaders"]);

chrome.notifications.onButtonClicked.addListener((_, buttonIndex) => {
    if(pendingRequest && buttonIndex === 0) {
        console.log(pendingRequest);
        const { url, method, requestHeaders, requestBody } = pendingRequest;
        console.log(url, method, requestHeaders, requestBody);

        const headers = {};
        if(requestHeaders !== undefined) {
            requestHeaders.forEach(header => {
                headers[header.name] = header.value;
            });
        }

        if(chrome.cookies !== undefined) {
            chrome.cookies.getAll({ url }, (cookies) => {
                const cookieHeader = cookies.map(cookie => `${cookie.name}=${cookie.value}`).join('; ');
                if(!headers['Cookie']) {
                    headers['Cookie'] = cookieHeader;
                }
            });
        }

        allowedRequest = pendingRequest;
        fetch(url, {
            method: method,
            headers: headers,
            body: requestBody ? requestBody.raw : null
        })
        .then(response => response.text())
        .then((data) => {
            chrome.tabs.create({ url: 'data:text/html;charset=utf-8,' + encodeURIComponent(data) });
            chrome.notifications.create({
                type: 'basic',
                iconUrl: 'logo.png',
                title: 'Request Allowed',
                message: `Request to ${url} was allowed.`
            });
        })
        .catch(() => {
            chrome.notifications.create({
                type: 'basic',
                iconUrl: 'logo.png',
                title: 'Request Failed',
                message: `Failed to simulate request to ${url}. You may want to turn off PhishNet temporarily.`
            });
        });
        pendingRequest = null;
    }
});