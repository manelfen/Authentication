const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const { Gateway, Wallets } = require('fabric-network');
const path = require('path');
const fs = require('fs');
const { ec: EC } = require('elliptic');
const forge = require('node-forge');
const ec = new EC('p256');
const https = require('https');
const app = express();
app.use(bodyParser.json());

/* ========== 📌 VARIABLES GLOBALES (pour réutilisation) ========== */
const gatewayInstances = {}; // { reg1channel: { gateway, contract }, globalchannel: { gateway, contract } }
const MY_SERVER_ID = 'serverA';
/* ========== 📌 FONCTIONS UTILES ========== */

// Vérification de la signature locale
function verifySignature(message, certPem, signatureB64) {
    const cert = crypto.createPublicKey(certPem);
    const publicKeyJwk = cert.export({ format: 'jwk' });

    const x = Buffer.from(publicKeyJwk.x, 'base64');
    const y = Buffer.from(publicKeyJwk.y, 'base64');

    const pubKey = ec.keyFromPublic({ x: x.toString('hex'), y: y.toString('hex') });

    const hash = crypto.createHash('sha256').update(message).digest();
    const signature = Buffer.from(signatureB64, 'base64');

    if (signature.length !== 64) {
        throw new Error('Invalid signature length (must be 64 bytes)');
    }

    const r = signature.slice(0, 32);
    const s = signature.slice(32);

    return pubKey.verify(hash, { r: r.toString('hex'), s: s.toString('hex') });
}

// Vérifie l'existence locale du device
function checkDeviceExistence(deviceId) {
    const certPath = path.join(__dirname, `fabric-ca-client/${deviceId}/msp/signcerts`);
    return fs.existsSync(certPath);
}

function checkUserExistence(userId) {
    const certPath = path.join(__dirname, `fabric-ca-client2/${userId}/msp/signcerts`);
    return fs.existsSync(certPath);
}

/* ========== ⚡ INITIALISATION DES GATEWAY (au démarrage) ========== */

async function initGateway(channelName, contractName, instanceKey) {
    const wallet = await Wallets.newFileSystemWallet('./wallet');
    const gateway = new Gateway();

    const ccpPath = path.resolve(__dirname, 'connection-profile.json');
    const ccp = JSON.parse(fs.readFileSync(ccpPath, 'utf8'));

    await gateway.connect(ccp, { wallet, identity: 'admin-orgmain', discovery: { enabled: false, asLocalhost: true } });
    const network = await gateway.getNetwork(channelName);
    const contract = network.getContract(contractName);

    gatewayInstances[instanceKey] = { gateway, contract };
    console.log(`✅ Gateway initialized for ${instanceKey} (${channelName})`);
}

/* ========== 🟢 AUTHENTIFICATION FONCTIONS (réutilisent instances) ========== */
async function getPeersByNames(network, namesArray) {
    const channel = network.getChannel();
    const allPeers = channel.getEndorsers();
    return allPeers.filter(p => namesArray.includes(p.name));
}

// Mise à jour Local Authentication sur reg1channel
async function updateLocalAuth(deviceId, status, timestampLocal) {
    const { contract } = gatewayInstances['reg1'];
    const network = await gatewayInstances['reg1'].gateway.getNetwork('reg1channel');

    const tx = contract.createTransaction('SetLocalAuthenticated');

    const endorsingPeers = await getPeersByNames(network, [
        'peer0.orgmain','peer1.orgmain','peer2.orgmain']);
    tx.setEndorsingPeers(endorsingPeers);

    await tx.submit(deviceId, status.toString(),timestampLocal);
}
async function updateGlobalAuth(deviceId, status , timestamp) {
   const { contract } = gatewayInstances['global'];
    const network = await gatewayInstances['global'].gateway.getNetwork('globalchannel');

    const tx = contract.createTransaction('SetRegionalAuthenticated');

    const endorsingPeers = await getPeersByNames(network, [
        'peer2.orgmain',
        'peer5.orgmain'
    ]);
    tx.setEndorsingPeers(endorsingPeers);

    await tx.submit(deviceId, status.toString(), timestamp);
    }

// Authentification régionale
async function authenticateRegional(deviceId, certPem, signatureB64, timestamp, serverID, edgeID, regionID) {
    const { contract } = gatewayInstances['reg1'];
    const network = await gatewayInstances['reg1'].gateway.getNetwork('reg1channel');

    const tx = contract.createTransaction('AuthenticateDeviceRegional');

    const endorsingPeers = await getPeersByNames(network, [
        'peer0.orgmain','peer1.orgmain','peer2.orgmain'
        ]);
    tx.setEndorsingPeers(endorsingPeers);

    console.log("🔍 Envoi aux peers: ", tx.getTransactionId());

    const result = await tx.submit(deviceId, certPem, signatureB64, timestamp, serverID, edgeID, regionID);

    const resultString = result.toString();
    console.log("↩️ Résultat brut du smart contract:", resultString);

    let parsed;
    try {
        parsed = JSON.parse(resultString);
        if (Array.isArray(parsed) && parsed.length > 0) {
            parsed = parsed[0];
        }
    } catch (e) {
        parsed = { success: false, message: "Réponse non JSON: " + resultString };
    }

    return parsed;

}

// Authentification interrégionale
// Authentification interrégionale — via peer2 uniquement
async function authenticateInterregional(deviceId, certPem, signatureB64, timestamp, serverID, edgeID, regionID) {
    const { contract, gateway } = gatewayInstances['global'];
    const network = await gateway.getNetwork('globalchannel');

    const tx = contract.createTransaction('AuthenticateDeviceInterregional');

    const endorsingPeers = await getPeersByNames(network, [
        'peer2.orgmain',
        'peer5.orgmain'
    ]);
    tx.setEndorsingPeers(endorsingPeers);

    try {
        const result = await tx.submit(deviceId, certPem, signatureB64, timestamp, serverID, edgeID, regionID);
        const resultString = result.toString();
        console.log("↩️ Résultat brut du smart contract (interregional):", resultString);

        let parsed;
        try {
            parsed = JSON.parse(resultString);
        } catch (e) {
            parsed = { success: false, message: "Réponse non JSON: " + resultString };
        }

        return parsed;

    } catch (err) {
        console.error("❌ Erreur lors de l'exécution de la transaction interrégionale :", err.message);
        return { success: false, message: "Échec de l'exécution interrégionale : " + err.message };
    }
}

// 🔧 Vérifie si le certificat du device est révoqué
function isRevoked(deviceId) {
    const data = JSON.parse(fs.readFileSync(path.join(__dirname, 'revoked.json')));
    return data.revoked.includes(deviceId);
}
function isRevokeduser(userId) {
    const data = JSON.parse(fs.readFileSync(path.join(__dirname, 'revoked.json')));
    return data.revoked.includes(userId);
}

function revokeDevice(deviceId) {
    const pathToFile = path.join(__dirname, 'revoked.json');
    const data = JSON.parse(fs.readFileSync(pathToFile));
    if (!data.revoked.includes(deviceId)) {
        data.revoked.push(deviceId);
        fs.writeFileSync(pathToFile, JSON.stringify(data, null, 2));
        console.log(`❌ Device ${deviceId} révoqué.`);
    }
}

function revokeuser(userId) {
    const pathToFile = path.join(__dirname, 'revoked.json');
    const data = JSON.parse(fs.readFileSync(pathToFile));
    if (!data.revoked.includes(userId)) {
        data.revoked.push(userId);
        fs.writeFileSync(pathToFile, JSON.stringify(data, null, 2));
        console.log(`❌ User ${userId} révoqué.`);
    }
}

// 🔒 Vérifie si déjà authentifié localement
function isAlreadyAuthenticated(deviceId) {
    const data = JSON.parse(fs.readFileSync(path.join(__dirname, 'authenticated.json')));
    return data.authenticated.includes(deviceId);
}

function isAlreadyAuthenticateduser(userId) {
    const data = JSON.parse(fs.readFileSync(path.join(__dirname, 'authenticated.json')));
    return data.authenticated.includes(userId);
}

function markAuthenticated(deviceId, timestampLocal) {
    const pathToFile = path.join(__dirname, 'authenticated.json');
    const data = fs.existsSync(pathToFile)
        ? JSON.parse(fs.readFileSync(pathToFile))
        : { devices: {} };

    if (!data.devices) data.devices = {};

    const now = Date.now();

    if (!data.devices[deviceId]) {
        // Première authentification
        data.devices[deviceId] = {
            timestampLocal,
            counter: 1
        };
        fs.writeFileSync(pathToFile, JSON.stringify(data, null, 2));
        console.log(`✅ Device ${deviceId} authentifié pour la première fois.`);
        return { status: 'auth_ok' };
    }

    const current = parseInt(data.devices[deviceId].timestampLocal);

    if (now - current < 15 * 60 * 1000) {
        data.devices[deviceId].counter++;
        if (data.devices[deviceId].counter >= 4) {
            revokeDevice(deviceId);
            delete data.devices[deviceId];
            fs.writeFileSync(pathToFile, JSON.stringify(data, null, 2));
            console.log(`⛔ Device ${deviceId} révoqué après 4 tentatives.`);
            return { status: 'revoked' };
        }

        fs.writeFileSync(pathToFile, JSON.stringify(data, null, 2));
        console.log(`🔁 Device ${deviceId} déjà authentifié (${data.devices[deviceId].counter} tentatives).`);
        return { status: 'already_authenticated' };
    }

    // ❗ Timestamp expiré → suppression
    delete data.devices[deviceId];
    fs.writeFileSync(pathToFile, JSON.stringify(data, null, 2));
    console.log(`⏱️ Timestamp expiré. Device ${deviceId} supprimé de authenticated.json.`);
    return { status: 'expired' };
}



function markAuthenticateduser(userId) {
    const pathToFile = path.join(__dirname, 'authenticated.json');
    const data = JSON.parse(fs.readFileSync(pathToFile));
    if (!data.authenticated.includes(userId)) {
        data.authenticated.push(userId);
        fs.writeFileSync(pathToFile, JSON.stringify(data, null, 2));
        console.log(`✅ user ${userId} marqué comme authentifié.`);
    }
}

// 🔎 Vérifie que le certificat reçu correspond à celui stocké localement
function isCertMatchingStored(deviceId, certPem) {
    const certPath = path.join(__dirname, `fabric-ca-client/${deviceId}/msp/signcerts`);
    if (!fs.existsSync(certPath)) return false;
    const files = fs.readdirSync(certPath);
    if (files.length === 0) return false;
    const storedCert = fs.readFileSync(path.join(certPath, files[0]), 'utf8');
    return storedCert === certPem;
}

function isCertMatchingStoreduser(userId, certPem) {
    const certPath = path.join(__dirname, `fabric-ca-client2/${userId}/msp/signcerts`);
    if (!fs.existsSync(certPath)) return false;
    const files = fs.readdirSync(certPath);
    if (files.length === 0) return false;
    const storedCert = fs.readFileSync(path.join(certPath, files[0]), 'utf8');
    return storedCert === certPem;
}

// 📆 Vérifie la validité temporelle du certificat

function verifyCertificateFields(certPem) {
    console.log("📥 Début de la vérification du certificat...");

    try {
        const x509 = new crypto.X509Certificate(certPem);

        console.log("📄 Certificat analysé :");
        console.log(" - Subject :", x509.subject);
        console.log(" - Issuer  :", x509.issuer);
        console.log(" - Valid From :", x509.validFrom);
        console.log(" - Valid To   :", x509.validTo);

        const now = new Date();
        console.log("🕒 Date actuelle :", now.toISOString());

        const notBefore = new Date(x509.validFrom);
        const notAfter = new Date(x509.validTo);

        if (now < notBefore || now > notAfter) {
            throw new Error(`Certificat expiré ou non encore valide : ${notBefore} -> ${notAfter}`);
        }

        const caCertPath = path.join(__dirname, 'ca-cert.pem');
        if (!fs.existsSync(caCertPath)) {
            throw new Error(`Certificat du CA introuvable à : ${caCertPath}`);
        }

        const caCertPem = fs.readFileSync(caCertPath, 'utf8');
        const caX509 = new crypto.X509Certificate(caCertPem);

        console.log("🔐 Certificat CA chargé avec succès.");
        console.log(" - CA Subject :", caX509.subject);
        console.log(" - CA Issuer  :", caX509.issuer);

        if (x509.issuer !== caX509.subject) {
            throw new Error(`❌ L'issuer du certificat ne correspond pas au CA. Cert issuer: ${x509.issuer}`);
        }

        // 🔍 Vérification de la signature du certificat avec la clé publique du CA
        const isVerified = x509.verify(caX509.publicKey);
        console.log(`🔐 Résultat de la vérification de la signature : ${isVerified ? "✅ OK" : "❌ Échec"}`);

        if (!isVerified) {
            throw new Error("Signature invalide : le certificat n'a pas été signé par le CA.");
        }

        // ✅ Extraction du CN
        const cnMatch = x509.subject.match(/CN=([^,\/]+)/);
        const cn = cnMatch ? cnMatch[1] : null;

        if (!cn) throw new Error("Impossible d'extraire le CN.");

        console.log("✔ CN extrait :", cn);
        console.log("✅ Device certificate verified successfuly.");

        return cn; // tu peux retourner le CN si besoin
    } catch (err) {
        console.error("❌ Error when verifying the certificate :", err.message);
        throw err;
    }
}
async function revokeDeviceEverywhere(deviceId) {
    // 🔁 Révoque dans reg1channel (régional)
    const contractReg1 = gatewayInstances['reg1'].contract;
    await contractReg1.submitTransaction('RevokeDevice', deviceId);

    // 🌐 Révoque dans globalchannel (interrégional)
    const contractGlobal = gatewayInstances['global'].contract;
    await contractGlobal.submitTransaction('RevokeDevice', deviceId); // plus besoin de setEndorsingPeers
}

function isTimestampValid(timestamp) {
	const now = Date.now();
	const ts = parseInt(timestamp, 10);
	return Math.abs(now - ts) <= 5 * 60 * 1000; // 5 minutes de tolérance
}

/* ========== 🚀 ROUTE PRINCIPALE ========== */

app.post('/authenticate', async (req, res) => {
    const {
    deviceId,
    userId,
    certPem,
    signatureB64,
    timestamp,
    authType,
    serverID,
    edgeID,
    regionID
} = req.body;

if (serverID !== MY_SERVER_ID) {
    return res.status(403).json({
        success: false,
        code: 'INVALID_SERVER',
        message: `❌ Mauvais serverID. Reçu : ${serverID}, attendu : ${MY_SERVER_ID}`
    });
}
   let message = '';
let message2 = '';
    try {
      if (authType === 'local') {  message = deviceId + serverID + timestamp + certPem;
    // 1. Est-il révoqué ?
    if (isRevoked(deviceId)) {
        return res.status(200).json({
            success: false,
            code: 'REVOKED',
            message: `❌ Device revoked after 4 tentatives.`
        });
    }

    // 2. Le certificat existe-t-il ?
    if (!checkDeviceExistence(deviceId)) {
        return res.status(404).json({ error: '❌ Certificat not found' });
    }

    // 3. Est-ce qu’il est déjà authentifié localement (timestamp local encore valide) ?
    const pathToFile = path.join(__dirname, 'authenticated.json');
    const data = fs.existsSync(pathToFile)
        ? JSON.parse(fs.readFileSync(pathToFile))
        : { devices: {} };

    const record = data.devices[deviceId];
    const now = Date.now();

   if (record) {
    const isStillValid = now - parseInt(record.timestampLocal) < 15 * 60 * 1000;

    if (isStillValid) {
        record.counter++;

        if (record.counter >= 4) {
            revokeDevice(deviceId);
            delete data.devices[deviceId];
            fs.writeFileSync(pathToFile, JSON.stringify(data, null, 2));
            return res.status(200).json({
                success: false,
                code: 'REVOKED',
                message: `❌ Device revoked after 4 tentatives.`
            });
        }

        fs.writeFileSync(pathToFile, JSON.stringify(data, null, 2));
        return res.status(200).json({
            success: true,
            code: 'ALREADY_AUTHENTICATED',
            message: `🔁 Device ${deviceId} is already authenticated (${record.counter} tentative(s)).`
        });
    } else {
        // timestamp local expiré
        delete data.devices[deviceId];
        fs.writeFileSync(pathToFile, JSON.stringify(data, null, 2));

        return res.status(200).json({
            success: false,
            code: 'SESSION_EXPIRED',
            message: `⏱️ Session expirée pour ${deviceId}. Veuillez vous réauthentifier localement.`
        });
    }
}


    // 4. Timestamp fourni par le client est-il valide ?
    if (!isTimestampValid(timestamp)) {
        revokeDevice(deviceId);
         return res.status(200).json({
            success: false,
            code: 'Timestamp',
            message: `⏱️ Invalid timestamp.`
        });
    }

    // 5. Vérifier le certificat (valide, signé par le bon CA)
    try {
       verifyCertificateFields(certPem);
    } catch (err) {
        revokeDevice(deviceId);
   //     await revokeDeviceEverywhere(deviceId);
         return res.status(200).json({
            success: false,
            code: 'invalid',
            message: `❌ INVALID certificat.`
        });
    }

    // 6. Est-ce que le certificat correspond à celui stocké ?
    if (!isCertMatchingStored(deviceId, certPem)) {
        revokeDevice(deviceId);
       // await revokeDeviceEverywhere(deviceId);
        return res.status(200).json({
            success: false,
            code: 'mismatched',
            message: `❌ Certificat mismatched.`
        });
    }

    // 7. Vérification de la signature ECDSA
    const isValid = verifySignature(deviceId + certPem + timestamp + serverID, certPem, signatureB64);
    if (!isValid) { revokeDevice(deviceId);
        return res.status(200).json({
            success: false,
            code: 'sign',
            message: `❌ Invalid signature.`
        });
    }

    // ✅ 8. Authentification réussie — maintenant on écrit dans authenticated.json
    const timestampLocal = Date.now().toString();
    data.devices[deviceId] = {
        timestampLocal,
        counter: 1
    };
    fs.writeFileSync(pathToFile, JSON.stringify(data, null, 2));
    console.log(`✅ Device ${deviceId} authentifié localement.`);

    res.status(200).json({
        success: true,
        code: 'OK',
        message: `✅ Local authentication successful ${deviceId}`
    });

    // 🔁 Mise à jour de la blockchain en arrière-plan
    setImmediate(async () => {
        try {
            await updateLocalAuth(deviceId, true, timestampLocal);
            console.log(`🔄 Mise à jour blockchain locale réussie pour ${deviceId}`);
        } catch (err) {
            console.error(`⚠️ Erreur lors de la mise à jour locale de ${deviceId} :`, err.message);
        }
    });
}


else if (authType === 'localuser') {
    message2 = userId + serverID + timestamp + certPem;

    // 🛑 1. Revoked?
    if (isRevokeduser(userId)) {
        return res.status(403).json({
            success: false,
            code: 'REVOKED',
            error: `❌ User ${userId} has been revoked.`
        });
    }

    // 📁 2. Load authenticated.json
    const authPath = path.join(__dirname, 'authenticated.json');
    const data = fs.existsSync(authPath)
        ? JSON.parse(fs.readFileSync(authPath))
        : { devices: {}, users: {} };
    if (!data.users) data.users = {};

    const now = Date.now();

    // 🔁 3. Already authenticated?
    if (data.users[userId]) {
        const authInfo = data.users[userId];
        const last = parseInt(authInfo.timestampLocal);

        const isStillValid = now - last < 15 * 60 * 1000;

        if (isStillValid) {
            authInfo.counter++;
            if (authInfo.counter >= 4) {
                revokeuser(userId);
                delete data.users[userId];
                fs.writeFileSync(authPath, JSON.stringify(data, null, 2));
                return res.status(403).json({
                    success: false,
                    code: 'REVOKED',
                    message: `⛔ User ${userId} has been revoked after 4 attempts.`
                });
            }

            fs.writeFileSync(authPath, JSON.stringify(data, null, 2));
            return res.status(200).json({
                success: true,
                code: 'ALREADY_AUTHENTICATED',
                message: `🔁 User ${userId} is already authenticated (${authInfo.counter} attempt(s)).`
            });
        } else {
            // ⏱️ Session expired → delete and ask for re-auth
            delete data.users[userId];
            fs.writeFileSync(authPath, JSON.stringify(data, null, 2));

            return res.status(200).json({
                success: false,
                code: 'SESSION_EXPIRED',
                message: `⏱️ Session expired for user ${userId}. Please re-authenticate locally.`
            });
        }
    }

    // 📂 4. Certificate exists?
    if (!checkUserExistence(userId)) {
        return res.status(404).json({ error: '❌ Certificate not found.' });
    }

    // 📆 5. Certificate valid?
    try {
        verifyCertificateFields(certPem);
    } catch (err) {
        revokeuser(userId);
       return res.status(200).json({
            success: false,
            code: 'cert',
            message: `❌ Invalid Certificate `
        });
    }

    // 🧾 6. Certificate matches stored one?
    if (!isCertMatchingStoreduser(userId, certPem)) {
        revokeuser(userId);
        return res.status(200).json({
            success: false,
            code: 'REVOKED',
            message: `❌ Certificate mismatched`
        });
    }

    // ⏱️ 7. Timestamp valid?
    if (!isTimestampValid(timestamp)) {
        revokeuser(userId);
        return res.status(200).json({
            success: false,
            code: 'REVOKED',
            message: `❌ Invalid timestamp.`
        });
    }

    // ✍️ 8. Signature valid?
    const isValid = verifySignature(userId + certPem + timestamp + serverID, certPem, signatureB64);
    if (!isValid) {
        revokeuser(userId);
        return res.status(200).json({
            success: false,
            code: 'REVOKED',
            message: `❌ Invalid signature.`
        });
    }

    // ✅ 9. Successful authentication — save session
    const timestampLocal = Date.now().toString();
    data.users[userId] = {
        timestampLocal,
        counter: 1
    };
    fs.writeFileSync(authPath, JSON.stringify(data, null, 2));
    console.log(`✅ User ${userId} successfully authenticated.`);

    return res.status(200).json({
        success: true,
        code: 'OK',
        message: `✅ Local authentication successful for user ${userId}.`
    });
}

else if (authType === 'intraregional') {  message = deviceId + serverID + edgeID + regionID + timestamp + certPem;
    const result = await authenticateRegional(deviceId, certPem, signatureB64, timestamp, serverID , edgeID, regionID);
    res.json(result); 
    const regionalTimestamp = result.regionalAuthTimestamp;
    // renvoie exactement ce que retourne le smart contract
if (result.success === true || result.success === 'true' && result.RegionalAuthTimestamp) {

    setImmediate(async () => {
        try {
            await updateGlobalAuth(deviceId, true, regionalTimestamp );
            console.log(`🌍 Mise à jour globale de regionauth réussie pour ${deviceId}`);
        } catch (err) {
            console.error(`⚠️ Erreur lors de la mise à jour globale de regionauth pour ${deviceId} :`, err.message);
        }
    });
}

}
 else if (authType === 'interregional') {  message = deviceId + serverID + edgeID + regionID + timestamp + certPem;
           const result = await authenticateInterregional(deviceId, certPem, signatureB64, timestamp, serverID , edgeID, regionID);
            res.json(result);

        } else {
            res.status(400).json({ error: 'Invalid authentication type' });
        }

    } catch (error) {
        console.error('❌ Error during authentication:', error.message);
        res.status(500).json({ error: error.message });
    }
});

/* ========== 🛑 FERMETURE PROPRE DU SERVEUR (déconnexion) ========== */
async function closeGateways() {
    for (const key of Object.keys(gatewayInstances)) {
        await gatewayInstances[key].gateway.disconnect();
        console.log(`🛑 Gateway disconnected for ${key}`);
    }
}

/* ========== 🚀 LANCEMENT SERVEUR ========== */

const PORT = 7000;

// 🔐 Charger les certificats TLS
const sslOptions = {
    key: fs.readFileSync('ssl/device-key.pem'),
    cert: fs.readFileSync('ssl/device-cert.pem')
};

// 🔐 Créer serveur HTTPS
const server = https.createServer(sslOptions, app);

async function startServer() {
    try {
        await initGateway('reg1channel', 'intraa', 'reg1');
        await initGateway('globalchannel', 'master', 'global');

        server.listen(PORT, () => {
            console.log(`🚀 Server HTTPS listening on port ${PORT}`);
        });
    } catch (err) {
        console.error('❌ Failed to initialize gateways:', err);
        process.exit(1);
    }
}

console.log('📦 Script chargé, démarrage du serveur HTTPS...');
startServer();

// 🔁 Shutdown propre
process.on('SIGINT', async () => {
    console.log('\n🛑 Shutting down server...');
    await closeGateways();
    process.exit(0);
});



