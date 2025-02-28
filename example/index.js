import express from "express";
import {createHash, createHmac} from 'crypto';

const app = express();

app.set('view engine', 'ejs');
// This is done so the raw request body can be extracted.
app.use(express.raw({type: '*/*'}));

const PUBLIC_KEY = 'hsp_pub_2078d1e8d7373674dd68577e0817d38a';
const PRIVATE_KEY = 'hsp_pri_4e253c9dc91f5cb2843a5d54e43081d528ef2eee11801b0461a327f5';

app.get('/', (req, res) => {
    res.render('index', {
        called: req.query.called,
        responseStatus: req.query.responseStatus,
        example: req.query.example,
        timestamp: req.query.timestamp,
    });
});

const queryString = req => {
    return Object
        .keys(req.query)
        .sort()
        .map(key => `${key}=${encodeURIComponent(req.query[key])}`)
        .join('&');
}

const parseAuthHeader = req => {
    if (!req.headers.authorization) {
        return null;
    }

    return req
        .headers
        .authorization
        .replace('HSP1-HMAC-SHA256 ', '')
        .split(',')
        .reduce((map, cur) => {
            const curArr = cur.split('=');
            map[curArr[0]] = curArr[1];
            return map;
        }, {});
}

const createHeadersString = (req, authHeader) => {
    return authHeader
        .headers
        .split(';')
        .sort()
        .map(headerName => `${headerName}:${req.headers[headerName]}`)
        .join('\n');
}

const sha256 = data => createHash('sha256').update(data).digest('hex');

const hmacSha256Hex = (key, data) => createHmac('sha256', key).update(data).digest('hex');


// This endpoint plays back a recorded call captured from our test environment
// It also includes query params to help make those work if needed.
app.post('/playrecordedinstallcall', async (_, res) => {
    const response = await fetch('http://10.0.64.112:4000/install?user_id=1&company_id=4&sort=name,created_at&limit=5&activeOnly', {
        method: 'POST',
        headers: {
            'content-type': 'application/json;charset=UTF-8',
            'x-hs-platform-request-timestamp': 1739361956,
            'Authorization': 'HSP1-HMAC-SHA256 pub=hsp_pub_2078d1e8d7373674dd68577e0817d38a,sig=0eea4aad471b4877a3afb0efe9c22f685b8d643af4c2c410a75a68b6c2f8761c,headers=content-length;content-type;host;x-hs-platform-request-timestamp'
        },
        body: '{"companyId":2,"userId":2001,"installationId":"loYOjlVXd7KA"}'
    });

    res.redirect(`/?called=true&responseStatus=${response.status}&example=playrecordedinstallcall&timestamp=1739361956`);
});


// This endpoint is mimicking what Help Scout is doing when creating the signature and adding it to the Authorization
// header.
app.post('/callinstall', async (req, res) => {
    console.log('Starting the generate request that will call /install');

    const timestamp = Math.floor(Date.now() / 1000);
    console.log(`Will use this timestamp for the request: ${timestamp}`);

    const url = new URL('http://localhost:4000/install');
    console.log(`Is going to call the install endpoint on ${url}. Normally it won't be on the same server as the caller.`)

    // language=JSON
    const requestBody = `
      {
        "companyId": "1234",
        "userId": "54321",
        "installationId": "5678"
      }
    `;

    const headersToInclude = {host: url.host, 'x-hs-platform-request-timestamp': timestamp};

    const method = 'POST';
    const uri = url.pathname;
    const query = '';
    const headers = Object.keys(headersToInclude)
        .sort()
        .map(headerName => `${headerName}:${headersToInclude[headerName]}`)
        .join('\n');
    const bodySha = sha256(requestBody);

    const canonicalRequest = [
        method,
        uri,
        query,
        headers,
        bodySha
    ].join('\n');

    const stringToSign = [
        'HSP1-HMAC-SHA256',
        timestamp,
        sha256(canonicalRequest)
    ].join('\n');

    const signature = hmacSha256Hex(PRIVATE_KEY, stringToSign);

    const authHeader = `HSP1-HMAC-SHA256 pub=${PUBLIC_KEY},sig=${signature},headers=${Object.keys(headersToInclude).sort().join(';')}`;

    const request = new Request(url, {
        method: 'POST',
        headers: {
            ...headersToInclude,
            'Content-Type': 'application/json',
            'Authorization': authHeader
        },
        body: requestBody
    });

    const response = await fetch(request);

    res.redirect(`/?called=true&responseStatus=${response.status}&example=callinstall&timestamp=${timestamp}`);
});


// This endpoint illustrates how signature validation can be done.
app.post('/install', async (req, res) => {
    console.log('Called the install endpoint');

    const authHeader = parseAuthHeader(req);
    if (!authHeader) {
        console.log('We expect the authorization header to be present. If not we fail with a 401')
        res.sendStatus(401);
        return
    }

    const timestamp = req.headers['x-hs-platform-request-timestamp'];

    const method = req.method;
    const uri = req.path;
    const query = queryString(req);
    const headers = createHeadersString(req, authHeader);
    const bodySha = sha256(req.body);

    const canonicalRequest = [
        method,
        uri,
        query,
        headers,
        bodySha
    ].join('\n');

    console.log('Canonical request:');
    console.log('#'.repeat(80));
    console.log(canonicalRequest);
    console.log('#'.repeat(80));

    const stringToSign = [
        'HSP1-HMAC-SHA256',
        timestamp,
        sha256(canonicalRequest)
    ].join('\n');

    console.log('String to sign:');
    console.log('#'.repeat(80));
    console.log(stringToSign);
    console.log('#'.repeat(80));

    const generatedSignature = hmacSha256Hex(PRIVATE_KEY, stringToSign);
    const signatureMatch = generatedSignature === authHeader.sig;

    console.log(`Generated signature:    ${generatedSignature}`);
    console.log(`Signature from request: ${authHeader.sig}`);
    console.log(`Signature match:        ${signatureMatch}`);

    const publicKeyMatch = authHeader.pub === PUBLIC_KEY;
    console.log(`Public key match:       ${publicKeyMatch}`);

    res.sendStatus(signatureMatch ? 200 : 401);
});

app.listen(4000, async () => {
    console.log('Example app running on port 4000!');
});