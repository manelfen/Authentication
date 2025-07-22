// device9782.js - Client WebSocket sécurisé avec authentification mutuelle
const WebSocket = require('ws');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const asn1 = require('asn1.js');
const EC = require('elliptic').ec;
const ec = new EC('p256');

const DEVICE_ID = 'device9782'; 

function loadOwnCredentials(deviceId) {
    const certDir = path.join(__dirname, `fabric-ca-client/${deviceId}/msp/signcerts`);
    const keyDir = path.join(__dirname, `fabric-ca-client/${deviceId}/msp/keystore`);

    const certPem = fs.readFileSync(path.join(certDir, fs.readdirSync(certDir)[0]), 'utf8');
    const keyPem = fs.readFileSync(path.join(keyDir, fs.readdirSync(keyDir)[0]), 'utf8');

    return { certPem, keyPem };
}

function isTimestampValid(timestamp) {
    const now = Date.now();
    const ts = parseInt(timestamp, 10);
    return Math.abs(now - ts) <= 5 * 60 * 1000;
}

function verifyCertificateFields(certPem) {
    const x509 = new crypto.X509Certificate(certPem);
    const now = new Date();
    const notBefore = new Date(x509.validFrom);
    const notAfter = new Date(x509.validTo);

    if (now < notBefore || now > notAfter) throw new Error("Certificat expiré");

    const caCertPath = path.join(__dirname, 'ca-cert.pem');
    const caCertPem = fs.readFileSync(caCertPath, 'utf8');
    const caX509 = new crypto.X509Certificate(caCertPem);
    if (x509.issuer !== caX509.subject) throw new Error("Issuer incorrect");
    if (!x509.verify(caX509.publicKey)) throw new Error("Signature du certificat invalide");

    return true;
}

function verifySignature(message, certPem, signatureB64) {
    const cert = crypto.createPublicKey(certPem);
    const publicKeyJwk = cert.export({ format: 'jwk' });

    const x = Buffer.from(publicKeyJwk.x, 'base64');
    const y = Buffer.from(publicKeyJwk.y, 'base64');
    const pubKey = ec.keyFromPublic({ x: x.toString('hex'), y: y.toString('hex') });

    const hash = crypto.createHash('sha256').update(message).digest();
    const signature = Buffer.from(signatureB64, 'base64');

    const r = signature.slice(0, 32);
    const s = signature.slice(32);

    return pubKey.verify(hash, { r: r.toString('hex'), s: s.toString('hex') });
}

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

// === Lancement ===

const { certPem, keyPem } = loadOwnCredentials(DEVICE_ID);
const nonce1 = crypto.randomBytes(16).toString('hex');
const timestamp = Date.now().toString();

// ✅ Modification ici : on signe seulement nonce1
const message1 = nonce1;
const signature1 = signMessage(keyPem, message1);

const ws = new WebSocket('wss://localhost:8443', {
    rejectUnauthorized: false
});

ws.on('open', () => {
    console.log("🚀 Connexion sécurisée au serveur établie (device2)");

    const step1Payload = {
        step: 1,
        deviceId1: DEVICE_ID,
        cert1: certPem,
        nonce1,
        timestamp,
        signature1
    };

    ws.send(JSON.stringify(step1Payload));
    console.log("📤 Étape 1 envoyée");
});

ws.on('message', (data) => {
    try {
        const parsed = JSON.parse(data);

        if (parsed.step === 2) {
            console.log("📝 Étape 2 reçue de", parsed.deviceId2);

            if (!isTimestampValid(parsed.timestamp)) throw new Error("Timestamp invalide");
            verifyCertificateFields(parsed.cert2);
            const msg2 = parsed.deviceId2 + parsed.cert2 + parsed.nonce2 + parsed.timestamp;
            if (!verifySignature(msg2, parsed.cert2, parsed.signature2)) throw new Error("Signature de device2 invalide");

            const signature3 = signMessage(keyPem, parsed.nonce2);
            const step3Payload = {
                step: 3,
                signedNonce2: signature3,
                deviceId1: DEVICE_ID,
                cert1: certPem
            };

            ws.send(JSON.stringify(step3Payload));
            console.log("📤 Étape 3 envoyée (signature finale)");
        }
    } catch (err) {
        console.error("💥 Erreur :", err.message);
        ws.close();
    }
});

