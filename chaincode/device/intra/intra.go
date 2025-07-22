package main

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"time"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

type SmartContract struct {
	contractapi.Contract
}

type Device struct {
	ID                    string `json:"id"`
	Certificate           string `json:"certificate"`
	ServerID              string `json:"serverId"`
	EdgeID                string `json:"edgeId"`
	RegionID              string `json:"regionId"`
	RegionalAuthenticated bool   `json:"regional_authenticated"`
	LocalAuthenticated    bool   `json:"local_authenticated"`
	Revoked               bool   `json:"revoked"`
	RegionalAuthTimestamp string `json:"regionalAuthTimestamp"`
	RegionalAuthCounter   int    `json:"regionalAuthCounter"`
	LocalAuthTimestamp    string `json:"localAuthTimestamp"`
}

type AuthResponseWithTS struct {
	Success               bool   `json:"success"`
	Message               string `json:"message"`
	RegionalAuthTimestamp string `json:"regionalAuthTimestamp"`
}

type AuthResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

const trustedCACertPEM = `
-----BEGIN CERTIFICATE-----
MIICFzCCAb2gAwIBAgIUQNqq6hloTmyLjMaOrHLOClme/80wCgYIKoZIzj0EAwIw
aDELMAkGA1UEBhMCVVMxFzAVBgNVBAgTDk5vcnRoIENhcm9saW5hMRQwEgYDVQQK
EwtIeXBlcmxlZGdlcjEPMA0GA1UECxMGRmFicmljMRkwFwYDVQQDExBmYWJyaWMt
Y2Etc2VydmVyMB4XDTI1MDUyNzE1NDkwMFoXDTQwMDUyMzE1NDkwMFowaDELMAkG
A1UEBhMCVVMxFzAVBgNVBAgTDk5vcnRoIENhcm9saW5hMRQwEgYDVQQKEwtIeXBl
cmxlZGdlcjEPMA0GA1UECxMGRmFicmljMRkwFwYDVQQDExBmYWJyaWMtY2Etc2Vy
dmVyMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE/XViTMtnfiDyC8Un43Jonwmp
eg2OGg62VSGHn7riVaP7krDX52aefYNqwDtU59oAmo4Dnc69F0vre2NSS+0VdKNF
MEMwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEwHQYDVR0OBBYE
FGk2adq9Kzy2AhqC2bW5mKiIWqtcMAoGCCqGSM49BAMCA0gAMEUCIQDa3onJY8V3
dcOtrFD33d7N88HyXjj8jh/I44xRNe/fJQIgHDkYP5myzf/N+vDEgkqkglGbKUW3
oLqob0OxSpaW7yQ=
-----END CERTIFICATE-----

`

func createResponse(success bool, message string) (string, error) {
	resp := []AuthResponse{{Success: success, Message: message}}
	jsonResp, err := json.Marshal(resp)
	if err != nil {
		return "", err
	}
	return string(jsonResp), nil
}

func createResponseWithTimestamp(success bool, message, timestamp string) (string, error) {
	resp := []AuthResponseWithTS{{
		Success:               success,
		Message:               message,
		RegionalAuthTimestamp: timestamp,
	}}
	jsonResp, err := json.Marshal(resp)
	if err != nil {
		return "", err
	}
	return string(jsonResp), nil
}

func (s *SmartContract) RegisterDevice(ctx contractapi.TransactionContextInterface, id, cert, serverID, edgeID, regionID string) (string, error) {
	// Vérification de l'existence
	exists, err := s.DeviceExists(ctx, id)
	if err != nil {
		return createResponse(false, "internal error checking device existence")
	}
	if exists {
		return createResponse(false, "device already exists")
	}

	// Vérification que le certificat est bien signé par le CA attendu
	if err := verifyCertSignedByTrustedCA(cert); err != nil {
		return createResponse(false, "certificate not trusted – rejected during registration")
	}

	// Création du device
	device := Device{
		ID:                    id,
		Certificate:           cert,
		ServerID:              serverID,
		EdgeID:                edgeID,
		RegionID:              regionID,
		RegionalAuthenticated: false,
		LocalAuthenticated:    false,
		Revoked:               false,
		RegionalAuthTimestamp: "",
		RegionalAuthCounter:   0,
		LocalAuthTimestamp:    "",
	}

	if err := s.updateDevice(ctx, &device); err != nil {
		return createResponse(false, "failed to store device")
	}

	return createResponse(true, "device registered successfully")
}


func (s *SmartContract) AuthenticateDeviceRegional(ctx contractapi.TransactionContextInterface, id, certPem, signatureB64, requestTimestamp, serverID, edgeID, regionID string) (string, error) {
	device, err := s.GetDevice(ctx, id)
	if err != nil {
		return createResponse(false, "device not found")
	}

	if device.Revoked {
		return createResponse(false, "device is revoked")
	}

	if device.ServerID != serverID || device.EdgeID != edgeID || device.RegionID != regionID {
		s.RevokeDevice(ctx, id)
		return createResponse(false, "ID mismatch – device revoked")
	}

	if device.Certificate != certPem {
		s.RevokeDevice(ctx, id)
		return createResponse(false, "certificate mismatch – device revoked")
	}

	if err := verifyTimestamp(requestTimestamp); err != nil {
		s.RevokeDevice(ctx, id)
		return createResponse(false, "invalid timestamp – device revoked")
	}

	if device.RegionalAuthTimestamp != "" {
		if err := verifyTimestamp(device.RegionalAuthTimestamp); err == nil {
			device.RegionalAuthCounter++
			if device.RegionalAuthCounter >= 3 {
				s.RevokeDevice(ctx, id)
				return createResponse(false, "too many intraregional requests – device revoked")
			}
			_ = s.updateDevice(ctx, device)
			return createResponse(false, "intraregional session still valid")
		}
		device.RegionalAuthTimestamp = ""
		device.RegionalAuthCounter = 0
		_ = s.updateDevice(ctx, device)
		return createResponse(false, "intraregional session expired – please retry later")
	}

	if device.LocalAuthTimestamp == "" {
		return createResponse(false, "no valid session – please authenticate locally first")
	}
	if err := verifyTimestamp(device.LocalAuthTimestamp); err != nil {
		return createResponse(false, "local session expired – please authenticate locally again")
	}

	cert, err := parseCertificate(certPem)
	if err != nil {
		s.RevokeDevice(ctx, id)
		return createResponse(false, "invalid certificate format – device revoked")
	}
	if err := verifyCertificate(cert); err != nil {
		s.RevokeDevice(ctx, id)
		return createResponse(false, "invalid certificate – device revoked")
	}
	if err := verifyCertSignedByTrustedCA(certPem); err != nil {
		s.RevokeDevice(ctx, id)
		return createResponse(false, "certificate not trusted – device revoked")
	}

	message := id + serverID + edgeID + regionID +certPem + requestTimestamp
	valid, err := verifySignatureWithCert(message, cert, signatureB64)
	if err != nil || !valid {
		s.RevokeDevice(ctx, id)
		return createResponse(false, "invalid signature – device revoked")
	}
	txTimestamp, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return createResponse(false, "unable to get transaction timestamp")
	}
newTS := strconv.FormatInt(txTimestamp.Seconds*1000, 10)

	device.RegionalAuthenticated = true
	device.RegionalAuthTimestamp = newTS
	device.RegionalAuthCounter = 0

	if err := s.updateDevice(ctx, device); err != nil {
		return createResponse(false, "failed to update device after authentication")
	}

	return createResponseWithTimestamp(true, "intraregional authentication successful", newTS)
}

func (s *SmartContract) SetLocalAuthenticated(ctx contractapi.TransactionContextInterface, id string, value bool, timestamp string) error {
	device, err := s.GetDevice(ctx, id)
	if err != nil {
		return err
	}
	device.LocalAuthenticated = value
	if value {
		device.LocalAuthTimestamp = timestamp
	} else {
		device.LocalAuthTimestamp = ""
	}
	return s.updateDevice(ctx, device)
}

func (s *SmartContract) GetDevice(ctx contractapi.TransactionContextInterface, id string) (*Device, error) {
	deviceJSON, err := ctx.GetStub().GetState(id)
	if err != nil {
		return nil, fmt.Errorf("failed to read from world state: %v", err)
	}
	if deviceJSON == nil {
		return nil, fmt.Errorf("device %s does not exist", id)
	}
	var device Device
	err = json.Unmarshal(deviceJSON, &device)
	return &device, err
}

func (s *SmartContract) DeviceExists(ctx contractapi.TransactionContextInterface, id string) (bool, error) {
	deviceJSON, err := ctx.GetStub().GetState(id)
	if err != nil {
		return false, err
	}
	return deviceJSON != nil, nil
}

func (s *SmartContract) updateDevice(ctx contractapi.TransactionContextInterface, device *Device) error {
	deviceJSON, err := json.Marshal(device)
	if err != nil {
		return err
	}
	return ctx.GetStub().PutState(device.ID, deviceJSON)
}

func (s *SmartContract) RevokeDevice(ctx contractapi.TransactionContextInterface, id string) {
	device, err := s.GetDevice(ctx, id)
	if err != nil {
		return
	}
	device.Revoked = true
	device.LocalAuthenticated = false
	device.RegionalAuthenticated = false
	_ = s.updateDevice(ctx, device)
}

func parseCertificate(certPem string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(certPem))
	if block == nil {
		return nil, errors.New("failed to parse PEM block")
	}
	return x509.ParseCertificate(block.Bytes)
}

func verifyTimestamp(ts string) error {
	tsInt, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid timestamp: %v", err)
	}
	timestamp := time.UnixMilli(tsInt)
	now := time.Now().UTC()
	if timestamp.Before(now.Add(-15*time.Minute)) || timestamp.After(now.Add(15*time.Minute)) {
		return errors.New("timestamp not within range ±15min")
	}
	return nil
}

func verifyCertificate(cert *x509.Certificate) error {
	if cert.Issuer.CommonName != "fabric-ca-server" {
		return errors.New("invalid certificate issuer")
	}
	now := time.Now()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return errors.New("certificate is expired or not yet valid")
	}
	return nil
}

func verifyCertSignedByTrustedCA(certPem string) error {
	deviceCert, err := parseCertificate(certPem)
	if err != nil {
		return err
	}
	caCert, err := parseCertificate(trustedCACertPEM)
	if err != nil {
		return err
	}
	if err := deviceCert.CheckSignatureFrom(caCert); err != nil {
		return errors.New("certificate is not signed by trusted CA")
	}
	return nil
}

func verifySignatureWithCert(message string, cert *x509.Certificate, signatureB64 string) (bool, error) {
	pubKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return false, errors.New("certificate does not contain an ECDSA public key")
	}
	hash := sha256.Sum256([]byte(message))
	sigBytes, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil || len(sigBytes) != 64 {
		return false, errors.New("invalid ECDSA signature")
	}
	r := new(big.Int).SetBytes(sigBytes[:32])
	s := new(big.Int).SetBytes(sigBytes[32:])
	return ecdsa.Verify(pubKey, hash[:], r, s), nil
}

func main() {
	chaincode, err := contractapi.NewChaincode(&SmartContract{})
	if err != nil {
		fmt.Printf("Error creating chaincode: %s", err)
		return
	}
	if err := chaincode.Start(); err != nil {
		fmt.Printf("Error starting chaincode: %s", err)
	}
}

