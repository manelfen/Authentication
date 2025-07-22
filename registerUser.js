const { Gateway, Wallets } = require('fabric-network');
const path = require('path');
const fs = require('fs');

// === Paramètres personnalisés ===
const START_USER_ID = 6386;
const BATCH_SIZE = 10;

const SERVER_ID = 'serverA';     
const EDGE_ID = 'edgeB';          
const REGION_ID = 'reg1';         

async function main() {
  try {
    const ccpPath = path.resolve(__dirname, 'connection-profile.json');
    const ccp = JSON.parse(fs.readFileSync(ccpPath, 'utf8'));

    const wallet = await Wallets.newFileSystemWallet('./wallet');
    const gateway = new Gateway();

    await gateway.connect(ccp, {
      wallet,
      identity: 'admin-orgmain',
      discovery: { enabled: true, asLocalhost: true }
    });

    const networkReg = await gateway.getNetwork('reg1channel');
    const contractReg = networkReg.getContract('ur');

    const networkGlobal = await gateway.getNetwork('globalchannel');
    const contractGlobal = networkGlobal.getContract('usermaster');

    const usersPath = path.join(__dirname, 'fabric-ca-client2');
    const users = fs.readdirSync(usersPath, { withFileTypes: true })
      .filter(dirent => dirent.isDirectory())
      .map(dirent => dirent.name)
      .filter(userId => {
        const number = parseInt(userId.replace(/\D/g, ''));
        return number >= START_USER_ID;
      });

    const failedUsers = [];

    async function registerUser(userId) {
      const mspPath = path.join(usersPath, userId, 'msp', 'signcerts');
      if (!fs.existsSync(mspPath)) throw new Error(`MSP manquant pour ${userId}`);

      const certFiles = fs.readdirSync(mspPath);
      if (certFiles.length === 0) throw new Error(`Certificat manquant pour ${userId}`);

      const certPem = fs.readFileSync(path.join(mspPath, certFiles[0]), 'utf8');

      // 1️⃣ Enregistrement dans reg1channel
      try {
        const responseReg = await contractReg.submitTransaction('RegisterUser', userId, certPem, SERVER_ID, EDGE_ID, REGION_ID);
        console.log(`✅ ${userId} enregistré dans reg1channel : ${responseReg.toString()}`);
      } catch (err) {
        console.error(`❌ Échec reg1channel pour ${userId} : ${err.message}`);
      }

      // 2️⃣ Enregistrement dans globalchannel
      try {
        const responseGlobal = await contractGlobal.submitTransaction('RegisterUser', userId, certPem, SERVER_ID, EDGE_ID, REGION_ID);
        console.log(`✅ ${userId} enregistré dans globalchannel : ${responseGlobal.toString()}`);
      } catch (err) {
        console.error(`❌ Échec globalchannel pour ${userId} : ${err.message}`);
      }
    }

    for (let i = 0; i < users.length; i += BATCH_SIZE) {
      const batch = users.slice(i, i + BATCH_SIZE);

      const promises = batch.map(async userId => {
        try {
          console.log(`🚀 Tentative d'enregistrement de ${userId}...`);
          await registerUser(userId);
        } catch (err) {
          console.error(`❌ Échec général ${userId} : ${err.message}`);
          failedUsers.push(userId);
        }
      });

      await Promise.all(promises);
    }

    if (failedUsers.length > 0) {
      console.log(`🚨 Utilisateurs échoués : ${failedUsers.join(', ')}`);
    }

    await gateway.disconnect();

  } catch (error) {
    console.error(`❌ Erreur principale : ${error.message}`);
    process.exit(1);
  }
}

main();

