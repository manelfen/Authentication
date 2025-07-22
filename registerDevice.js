const { Gateway, Wallets } = require('fabric-network');
const path = require('path');
const fs = require('fs');

const BATCH_SIZE = 10;
const SERVER_ID = 'serverA';
const EDGE_ID = 'edgeB';
const REGION_ID = 'reg1';

async function registerDevices(startIndex = 40000) {
  try {
    const ccpPath = path.resolve(__dirname, '..', 'pfev2', 'connection-profile.json');
    const ccp = JSON.parse(fs.readFileSync(ccpPath, 'utf8'));
    const wallet = await Wallets.newFileSystemWallet('./wallet');

    const gateway = new Gateway();
    await gateway.connect(ccp, {
      wallet,
      identity: 'admin-orgmain',
      discovery: { enabled: true, asLocalhost: true }
    });

    // 🔗 Connexion aux deux channels
    const globalNetwork = await gateway.getNetwork('globalchannel');
    const globalContract = globalNetwork.getContract('master');

    const reg1Network = await gateway.getNetwork('reg1channel');
    const reg1Contract = reg1Network.getContract('intraa');

    const devicesPath = path.join(__dirname, '..', 'pfev2', 'fabric-ca-client');
    const allDevices = fs.readdirSync(devicesPath, { withFileTypes: true })
      .filter(dirent => dirent.isDirectory() && dirent.name.startsWith('device'))
      .map(dirent => dirent.name)
      .filter(name => {
        const num = parseInt(name.replace('device', ''));
        return !isNaN(num) && num >= startIndex;
      })
      .sort((a, b) => parseInt(a.replace('device', '')) - parseInt(b.replace('device', '')));

    console.log(`🔍 ${allDevices.length} devices à enregistrer sur reg1channel & globalchannel.`);

    for (let i = 0; i < allDevices.length; i += BATCH_SIZE) {
      const batch = allDevices.slice(i, i + BATCH_SIZE);

      const promises = batch.map(async deviceId => {
        try {
          const certPath = path.join(devicesPath, deviceId, 'msp', 'signcerts');
          const certFiles = fs.readdirSync(certPath);
          if (certFiles.length === 0) throw new Error('Aucun certificat trouvé');

          const certPem = fs.readFileSync(path.join(certPath, certFiles[0]), 'utf8');

          // 🌍 Enregistrement global
          await globalContract.submitTransaction('RegisterDevice', deviceId, certPem, SERVER_ID, EDGE_ID, REGION_ID);
          console.log(`✅ ${deviceId} - enregistré sur globalchannel`);

          // 🌐 Enregistrement régional
          await reg1Contract.submitTransaction('RegisterDevice', deviceId, certPem, SERVER_ID, EDGE_ID, REGION_ID);
          console.log(`✅ ${deviceId} - enregistré sur reg1channel`);

        } catch (err) {
          console.error(`❌ ${deviceId} - ${err.message}`);
        }
      });

      await Promise.all(promises);
    }

    await gateway.disconnect();
    console.log('🎉 Enregistrement terminé sur les deux channels.');

  } catch (err) {
    console.error(`❌ Erreur générale : ${err.message}`);
    process.exit(1);
  }
}

registerDevices(40000);

