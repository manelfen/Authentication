const axios = require('axios');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const https = require('https');
const asn1 = require('asn1.js');
const readline = require('readline').createInterface({
    input: process.stdin,
    output: process.stdout
});

const RESPONSE_LOG_PATH = 'response_times.json';
const HARDCODED_SERVER_ID = 'serverA';
const HARDCODED_EDGE_ID = 'edgeB';
const HARDCODED_REGION_ID = 'reg1';

// Signature R||S
function signMessage(privateKeyPem, message) {
    const privateKey = crypto.createPrivateKey(privateKeyPem);
    const sign = crypto.createSign('SHA256');
    sign.update(message);
    sign.end();
    const signatureDER = sign.sign(privateKey);

    const ECDSASignatureASN = asn1.define('ECDSASignature', function () {
        this.seq().obj(this.key('r').int(), this.key('s').int());
    });

    const decoded = ECDSASignatureASN.decode(signatureDER, 'der');
    const r = Buffer.from(decoded.r.toArray('be', 32));
    const s = Buffer.from(decoded.s.toArray('be', 32));

    return Buffer.concat([r, s]).toString('base64');
}

// Chargement des certs/keys
async function loadAlldeviceCredentials(deviceIds) {
    const credentials = {};

    for (const deviceId of deviceIds) {
        const certDir = path.join(__dirname, `fabric-ca-client/${deviceId}/msp/signcerts`);
        const keyDir = path.join(__dirname, `fabric-ca-client/${deviceId}/msp/keystore`);

        if (!fs.existsSync(certDir) || !fs.existsSync(keyDir)) {
            throw new Error(`❌ Certificat ou clé manquant pour ${deviceId}.`);
        }

        const certPem = fs.readFileSync(path.join(certDir, fs.readdirSync(certDir)[0]), 'utf8');
        const keyPem = fs.readFileSync(path.join(keyDir, fs.readdirSync(keyDir)[0]), 'utf8');

        credentials[deviceId] = { certPem, keyPem };
    }

    return credentials;
}

// Envoi REST au serveur
async function sendAuthenticationRequest(deviceId, certPem, keyPem, authType, region) {
    const timestamp = Date.now().toString();
//const timestamp = (Date.now() - 20 * 60 * 1000).toString(); 
    let message;
    if (authType === 'local') {
        message = deviceId + certPem + timestamp + HARDCODED_SERVER_ID;
    } else {
        message = deviceId + HARDCODED_SERVER_ID + HARDCODED_EDGE_ID + HARDCODED_REGION_ID + certPem + timestamp;

    }

    const signatureB64 = signMessage(keyPem, message);

    const payload = {
        deviceId,
        certPem,
        timestamp,
        signatureB64,
        authType,
        region: region || '',
        serverID: HARDCODED_SERVER_ID,
        edgeID: HARDCODED_EDGE_ID,
        regionID: HARDCODED_REGION_ID
    };

    const start = Date.now();
    try {
        const response = await axios.post('https://localhost:7000/authenticate', payload, {
            httpsAgent: new https.Agent({ rejectUnauthorized: false })
        });
        const duration = Date.now() - start;

        let responsePayload = response.data;
        if (Array.isArray(responsePayload)) {
            responsePayload = responsePayload[0];
        }

        const success = responsePayload.success === true || responsePayload.success === 'true';
        const message = responsePayload.message || 'Aucun message';
        console.log(`${success ? '✅' : '❌'} ${authType.toUpperCase()} for ${deviceId}  - ${message}`);

        return {
            deviceId,
            authType,
            responseTime: duration,
            success,
            message: responsePayload.message || ''
        };
    } catch (err) {
        const duration = Date.now() - start;
        console.error(`❌ ERROR for ${deviceId} (${authType}) :`, err.message);
        return { deviceId, authType, responseTime: duration, success: false, error: err.message };
    }
}

function prompt(question) {
    return new Promise(resolve => readline.question(question, answer => resolve(answer.trim())));
}

async function main() {
    try {
        const authType = await prompt('authentication type (local, intraregional, interregional): ');
        if (!['local', 'intraregional', 'interregional'].includes(authType)) throw new Error('Invalid Type.');

        const region = HARDCODED_REGION_ID;

        const idsInput = await prompt('devices id (separated with , ): ');
        const deviceIds = idsInput.split(',').map(id => id.trim()).filter(Boolean);

        const credentials = await loadAlldeviceCredentials(deviceIds);

        console.log(`🚀 Sending request(s) ${authType.toUpperCase()} ...\n`);
        const startAll = Date.now();

        const results = await Promise.all(deviceIds.map(deviceId =>
            sendAuthenticationRequest(deviceId, credentials[deviceId].certPem, credentials[deviceId].keyPem, authType, region)
        ));

        const endAll = Date.now();
        const duration = (endAll - startAll) / 1000;
        const avg = results.reduce((sum, r) => sum + r.responseTime, 0) / results.length;
        const tps = (results.length / duration).toFixed(2);
      //  const accuracy = ((results.filter(r => r.success).length / results.length) * 100).toFixed(2);

        console.log(`\n⏳ Global response time : ${duration.toFixed(3)} s`);
        console.log(`📊 Average response time : ${(avg / 1000).toFixed(3)} s`);
        console.log(`⚡ TPS : ${tps}`);
        fs.writeFileSync(RESPONSE_LOG_PATH, JSON.stringify(results, null, 2));
        console.log(`📝 results writen in  ${RESPONSE_LOG_PATH}`);

    } catch (err) {
        console.error('❌ General error :', err.message);
    } finally {
        readline.close();
    }
}


main();
