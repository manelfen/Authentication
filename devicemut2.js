const fs = require('fs');
const path = require('path');
const https = require('https');
const WebSocket = require('ws');
const crypto = require('crypto');
const asn1 = require('asn1.js');
const EC = require('elliptic').ec;
const ec = new EC('p256');

const DEVICE_ID = 'device9781';

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

    const isVerified = x509.verify(caX509.publicKey);
    if (!isVerified) throw new Error("Signature invalide du certificat");

    return true;
}

function isTimestampValid(timestamp) {
    const now = Date.now();
    const ts = parseInt(timestamp, 10);
    return Math.abs(now - ts) <= 5 * 60 * 1000;
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

function loadOwnCredentials(deviceId) {
    const certDir = path.join(__dirname, `fabric-ca-client/${deviceId}/msp/signcerts`);
    const keyDir = path.join(__dirname, `fabric-ca-client/${deviceId}/msp/keystore`);

    const certPem = fs.readFileSync(path.join(certDir, fs.readdirSync(certDir)[0]), 'utf8');
    const keyPem = fs.readFileSync(path.join(keyDir, fs.readdirSync(keyDir)[0]), 'utf8');

    return { certPem, keyPem };
}

// === Serveur HTTPS + WebSocket Secure (WSS) ===

const server = https.createServer({
    cert: fs.readFileSync(path.join(__dirname, 'ssl/device-cert.pem')),
    key: fs.readFileSync(path.join(__dirname, 'ssl/device-key.pem'))
});

const wss = new WebSocket.Server({ server });
server.listen(8443, () => {
    console.log("📡 device2 écoute en WSS sur https://localhost:8443");
});

wss.on('connection', ws => {
    console.log("🔗 Connexion entrante acceptée");

    const { certPem, keyPem } = loadOwnCredentials(DEVICE_ID);
    const nonce2 = crypto.randomBytes(16).toString('hex');

    ws.on('message', async (data) => {
        try {
            const parsed = JSON.parse(data);

            if (parsed.step === 1) {
                const { deviceId1, cert1, nonce1, signature1, timestamp } = parsed;

                console.log("📝 Étape 1 reçue de", deviceId1);
                if (!isTimestampValid(timestamp)) throw new Error("⏱️ Timestamp invalide");

                verifyCertificateFields(cert1);

                // ✅ Vérifie uniquement la signature de nonce1
                const msg1 = nonce1;
                if (!verifySignature(msg1, cert1, signature1)) throw new Error("Signature invalide device1");

                const ts2 = Date.now().toString();
                const msg2 = DEVICE_ID + certPem + nonce2 + ts2;
                const signature2 = signMessage(keyPem, msg2);

                const step2Payload = {
                    step: 2,
                    deviceId2: DEVICE_ID,
                    cert2: certPem,
                    nonce2,
                    timestamp: ts2,
                    signature2
                };
                ws.send(JSON.stringify(step2Payload));
                console.log("📤 Étape 2 envoyée");
            }

            else if (parsed.step === 3) {
                const isValid = verifySignature(nonce2, parsed.cert1, parsed.signedNonce2);

                if (!isValid) {
                    console.log("❌ Signature finale incorrecte");
                } else {
                    console.log("✅ Authentification mutuelle RÉUSSIE avec", parsed.deviceId1);
                }
                ws.close();
            }
        } catch (err) {
            console.error("💥 Erreur :", err.message);
            ws.close();
        }
    });
});

