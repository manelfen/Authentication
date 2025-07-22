#!/bin/bash

# Configuration
CA_SERVER="localhost:7054"
CA_ADMIN="admin:adminpw"
BASE_DIR="/home/manel/pfev2/fabric-ca-client"
DEFAULT_PASSWORD="devicepw"
CA_SERVER_HOME="/home/manel/pfev2/fabric-ca-server"

# Fonction pour trouver le dernier numéro de device existant
find_last_device_number() {
	local last_num=0
	for dir in "$BASE_DIR"/device*; do
    	if [[ -d "$dir" ]]; then
        	local num=${dir##*device}
        	if [[ $num =~ ^[0-9]+$ ]] && (( num > last_num )); then
            	last_num=$num
        	fi
    	fi
	done
	echo $last_num
}

# Fonction pour générer un certificat
generate_device() {
	local device_num=$1
	local device_name="device${device_num}"
    
	echo "⚙️  Génération pour $device_name..."
    
	export FABRIC_CA_CLIENT_HOME="$BASE_DIR"
    
	# Enregistrement
	echo "🔐 Enregistrement..."
	fabric-ca-client register --id.name "$device_name" --id.secret "$DEFAULT_PASSWORD" --id.type client -u "http://$CA_SERVER"
    
	# Génération MSP
	echo "📝 Génération des certificats..."
	fabric-ca-client enroll -u "http://${device_name}:${DEFAULT_PASSWORD}@${CA_SERVER}" -M "${BASE_DIR}/${device_name}/msp"
    
	# Vérification
	if [[ -f "${BASE_DIR}/${device_name}/msp/signcerts/cert.pem" ]]; then
    	echo "✅ Succès pour $device_name"
    	return 0
	else
    	echo "❌ Échec pour $device_name"
    	return 1
	fi
}

# Main
echo "=== Générateur de Certificats ==="
last_num=$(find_last_device_number)
next_num=$((last_num + 1))

echo ""
echo "Dernier device existant: device${last_num}"
echo "Procpfev2in numéro disponible: device${next_num}"
echo ""

read -p "Combien de certificats à générer ? " count

for ((i=next_num; i<next_num+count; i++)); do
	if ! generate_device "$i"; then
    	echo "Arrêt prématuré. Vérifiez les logs du serveur CA."
    	exit 1
	fi
	echo ""
done

echo "=== Résumé ==="
echo "Dernier device généré: device$((next_num + count - 1))"
echo "Emplacements:"
for ((i=next_num; i<next_num+count; i++)); do
	echo "- ${BASE_DIR}/device${i}/msp/signcerts/cert.pem"
done

