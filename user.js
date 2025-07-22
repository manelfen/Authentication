const axios = require('axios');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const https = require('https');
const asn1 = require('asn1.js');
const { Gateway, Wallets, DefaultEventHandlerStrategies } = require('fabric-network');
const readline = require('readline').createInterface({
    input: process.stdin,
    output: process.stdout
});

const RESPONSE_LOG_PATH = 'response_times.json';
const HARDCODED_SERVER_ID = 'serverA';
const HARDCODED_EDGE_ID = 'edgeB';
const HARDCODED_REGION_ID = 'reg1';

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

async function loadAllUserCredentials(userIds) {
    const credentials = {};
    for (const userId of userIds) {
        const certDir = path.join(__dirname, `fabric-ca-client2/${userId}/msp/signcerts`);
        const keyDir = path.join(__dirname, `fabric-ca-client2/${userId}/msp/keystore`);
        if (!fs.existsSync(certDir) || !fs.existsSync(keyDir)) {
            throw new Error(`❌ Certificat ou clé manquant pour ${userId}`);
        }

        const certPem = fs.readFileSync(path.join(certDir, fs.readdirSync(certDir)[0]), 'utf8');
        const keyPem = fs.readFileSync(path.join(keyDir, fs.readdirSync(keyDir)[0]), 'utf8');
        credentials[userId] = { certPem, keyPem };
    }
    return credentials;
}

async function authenticateLocally(userId, certPem, signatureB64, timestamp) {
    const response = await axios.post(
        'https://localhost:7000/authenticate',
        {
            userId,
            certPem,
            timestamp,
            signatureB64,
            authType: 'localuser',
            region: '',
            serverID: HARDCODED_SERVER_ID,
            edgeID: HARDCODED_EDGE_ID,
            regionID: HARDCODED_REGION_ID
        },
        {
            httpsAgent: new https.Agent({ rejectUnauthorized: false })
        }
    );
    return response.data;
}

async function initializeGateway(authType) {
    const region = HARDCODED_REGION_ID;
    const ccpPath = path.resolve(__dirname, 'connection-profile.json');
    const ccp = JSON.parse(fs.readFileSync(ccpPath, 'utf8'));

    const wallet = await Wallets.newFileSystemWallet('./wallet');
    const identity = await wallet.get('admin-orgmain');
    if (!identity) throw new Error(`Identité 'admin-orgmain' manquante.`);

    const gateway = new Gateway();
    await gateway.connect(ccp, {
        wallet,
        identity: 'admin-orgmain',
        discovery: { enabled: false, asLocalhost: true },
        eventHandlerOptions: {
            strategy: DefaultEventHandlerStrategies.NETWORK_SCOPE_ALLFORTX,
            commitTimeout: 300
        }
    });

    let channelName, contractName, peerNames;
    if (authType === 'intraregional') {
        channelName = `${region}channel`;
        contractName = 'ur';
        peerNames = ['peer0.orgmain', 'peer1.orgmain', 'peer2.orgmain'];
    } else if (authType === 'interregional') {
        channelName = 'globalchannel';
        contractName = 'usermaster';
        peerNames = ['peer2.orgmain', 'peer5.orgmain'];
    } else {
        throw new Error('Type d’authentification invalide');
    }

    const network = await gateway.getNetwork(channelName);
    const contract = network.getContract(contractName);
    const functionName = authType === 'intraregional' ? 'AuthenticateUserInterregional' : 'AuthenticateUserInterregional';

    const channel = network.getChannel();
    const peers = peerNames.map(name =>
        channel.getEndorsers('OrgMainMSP').find(p => p.name === name)
    ).filter(Boolean);

    if (peers.length !== peerNames.length) {
        throw new Error(`❌ Tous les peers ne sont pas disponibles`);
    }

    return { gateway, contract, functionName, peers };
}

async function authenticateUser(userId, credentials, authType, resultsArray, contract = null, functionName = '', peers = []) {
    try {
        const { certPem, keyPem } = credentials[userId];
     //  const timestamp = Date.now().toString();
const timestamp = (Date.now() - 20 * 60 * 1000).toString(); 
        const message = authType === 'localuser'
            ? userId + certPem + timestamp + HARDCODED_SERVER_ID
            : userId + HARDCODED_SERVER_ID + HARDCODED_EDGE_ID + HARDCODED_REGION_ID + certPem + timestamp;

        const signatureB64 = signMessage(keyPem, message);
        const start = Date.now();

        if (authType === 'localuser') {
            const result = await authenticateLocally(userId, certPem, signatureB64, timestamp);
            const end = Date.now();
            const responseTime = end - start;
            const success = result.success === true || result.success === 'true';
            const code = result.code || 'UNKNOWN';
            const msg = result.message || result.error || 'Aucune réponse message';

            console.log(`${success ? '✅' : '❌'} LOCALUSER pour ${userId} [${code}] - ${msg}`);
            resultsArray.push({ userId, authType, responseTime, success, code, message: msg });
            return;
        }

        const txn = contract.createTransaction(functionName);
        txn.setEndorsingPeers(peers);

        const txResult = await txn.submit(
            userId,
            certPem,
            signatureB64,
            timestamp,
            HARDCODED_SERVER_ID,
            HARDCODED_EDGE_ID,
            HARDCODED_REGION_ID
        );

        const end = Date.now();
        const responseTime = end - start;

        let parsed = {};
        try {
            parsed = JSON.parse(txResult.toString());
        } catch (e) {
            parsed = { success: false, message: txResult.toString() };
        }

        const first = Array.isArray(parsed) ? parsed[0] : parsed;
        const success = first.success === true || first.success === 'true';

        console.log(`${success ? '✅' : '❌'} ${authType.toUpperCase()} pour ${userId} - ${first.message || ''}`);
        resultsArray.push({
            userId,
            authType,
            responseTime,
            success,
            message: first.message || ''
        });

    } catch (err) {
        console.error(`❌ Erreur pour ${userId} (${authType}):`, err.message);
        resultsArray.push({ userId, authType, success: false, error: err.message });
    }
}

function prompt(question) {
    return new Promise(resolve => readline.question(question, answer => resolve(answer.trim())));
}

async function main() {
    try {
        const authType = await prompt('Type of authentication (localuser, intraregional, interregional): ');
        if (!['localuser', 'intraregional', 'interregional'].includes(authType)) throw new Error('invalid type');

        const idsInput = await prompt('Users Ids (separated with ,): ');
        const userIds = idsInput.split(',').map(id => id.trim()).filter(Boolean);
        const credentials = await loadAllUserCredentials(userIds);

        let contract, functionName, peers, gateway;
        if (authType !== 'localuser') {
            ({ gateway, contract, functionName, peers } = await initializeGateway(authType));
        }

        const results = [];
        const startAll = Date.now();

        await Promise.all(userIds.map(userId =>
            authenticateUser(userId, credentials, authType, results, contract, functionName, peers)
        ));

        const endAll = Date.now();
        if (gateway) await gateway.disconnect();

        const duration = (endAll - startAll) / 1000;
        const avg = results.reduce((sum, r) => sum + (r.responseTime || 0), 0) / results.length;
        const tps = (results.length / duration).toFixed(2);
        const accuracy = ((results.filter(r => r.success).length / results.length) * 100).toFixed(2);

        console.log(`\n⏳ Durée totale : ${duration.toFixed(3)} s`);
        console.log(`📊 Temps moyen : ${(avg / 1000).toFixed(3)} s`);
        console.log(`⚡ TPS : ${tps}`);
      //  console.log(`🎯 Accuracy : ${accuracy}%`);

        fs.writeFileSync(RESPONSE_LOG_PATH, JSON.stringify(results, null, 2));
        console.log(`📝 Résultats sauvegardés dans ${RESPONSE_LOG_PATH}`);
    } catch (err) {
        console.error('❌ Erreur générale :', err.message);
    } finally {
        readline.close();
    }
}

main();



