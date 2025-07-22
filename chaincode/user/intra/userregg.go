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

type User struct {
	ID                          string `json:"id"`
	Certificate                 string `json:"certificate"`
	ServerID                    string `json:"serverId"`
	EdgeID                      string `json:"edgeId"`
	RegionID                    string `json:"regionId"`
	InterregionalAuthenticated  bool   `json:"interregional_authenticated"`
	Revoked                     bool   `json:"revoked"`
	InterregionalAuthTimestamp string `json:"interregionalAuthTimestamp"`
	InterregionalAuthCounter   int    `json:"interregionalAuthCounter"`
}

type AuthResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

type AuthResponseWithTS struct {
	Success                     bool   `json:"success"`
	Message                     string `json:"message"`
	InterregionalAuthTimestamp string `json:"interregionalAuthTimestamp"`
}

const trustedCACertPEM = `-----BEGIN CERTIFICATE-----
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
		Success:                    success,
		Message:                    message,
		InterregionalAuthTimestamp: timestamp,
	}}
	jsonResp, err := json.Marshal(resp)
	if err != nil {
		return "", err
	}
	return string(jsonResp), nil
}

func (s *SmartContract) RegisterUser(ctx contractapi.TransactionContextInterface, id, cert, serverID, edgeID, regionID string) (string, error) {
	exists, err := s.UserExists(ctx, id)
	if err != nil {
		return createResponse(false, "internal error checking user existence")
	}
	if exists {
		return createResponse(false, "user already exists")
	}

	if err := verifyCertSignedByTrustedCA(cert); err != nil {
		return createResponse(false, "certificate not trusted")
	}

	user := User{
		ID:                         id,
		Certificate:                cert,
		ServerID:                   serverID,
		EdgeID:                     edgeID,
		RegionID:                   regionID,
		InterregionalAuthenticated: false,
		Revoked:                    false,
	}

	if err := s.updateUser(ctx, &user); err != nil {
		return createResponse(false, "failed to store user")
	}

	return createResponse(true, "user registered successfully")
}

func (s *SmartContract) AuthenticateUserInterregional(ctx contractapi.TransactionContextInterface, id, certPem, signatureB64, requestTimestamp, serverID, edgeID, regionID string) (string, error) {
	user, err := s.GetUser(ctx, id)
	if err != nil {
		return createResponse(false, "user not found")
	}

	if user.Revoked {
		return createResponse(false, "user is revoked")
	}

	if user.ServerID != serverID || user.EdgeID != edgeID || user.RegionID != regionID {
		s.RevokeUser(ctx, id)
		return createResponse(false, "ID mismatch – user revoked")
	}

	if user.Certificate != certPem {
		s.RevokeUser(ctx, id)
		return createResponse(false, "certificate mismatch – user revoked")
	}

	if err := verifyTimestamp(requestTimestamp); err != nil {
		s.RevokeUser(ctx, id)
		return createResponse(false, "invalid timestamp – user revoked")
	}

	if user.InterregionalAuthTimestamp != "" {
		if err := verifyTimestamp(user.InterregionalAuthTimestamp); err == nil {
			user.InterregionalAuthCounter++
			if user.InterregionalAuthCounter >= 3 {
				s.RevokeUser(ctx, id)
				return createResponse(false, "too many interregional requests – user revoked")
			}
			_ = s.updateUser(ctx, user)
			return createResponse(false, "interregional session still valid")
		}
		user.InterregionalAuthTimestamp = ""
		user.InterregionalAuthCounter = 0
		_ = s.updateUser(ctx, user)
		return createResponse(false, "interregional session expired – please retry later")
	}

	cert, err := parseCertificate(certPem)
	if err != nil {
		s.RevokeUser(ctx, id)
		return createResponse(false, "invalid certificate format – user revoked")
	}
	if err := verifyCertificate(cert); err != nil {
		s.RevokeUser(ctx, id)
		return createResponse(false, "invalid certificate – user revoked")
	}
	if err := verifyCertSignedByTrustedCA(certPem); err != nil {
		s.RevokeUser(ctx, id)
		return createResponse(false, "certificate not trusted – user revoked")
	}

	message := id + serverID + edgeID + regionID + certPem + requestTimestamp
	valid, err := verifySignatureWithCert(message, cert, signatureB64)
	if err != nil || !valid {
		s.RevokeUser(ctx, id)
		return createResponse(false, "invalid signature – user revoked")
	}

	txTimestamp, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return createResponse(false, "unable to get transaction timestamp")
	}
	newTS := strconv.FormatInt(txTimestamp.Seconds*1000, 10)

	user.InterregionalAuthenticated = true
	user.InterregionalAuthTimestamp = newTS
	user.InterregionalAuthCounter = 0

	if err := s.updateUser(ctx, user); err != nil {
		return createResponse(false, "failed to update user after authentication")
	}

	return createResponseWithTimestamp(true, "interregional authentication successful", newTS)
}

func (s *SmartContract) GetUser(ctx contractapi.TransactionContextInterface, id string) (*User, error) {
	userJSON, err := ctx.GetStub().GetState(id)
	if err != nil {
		return nil, fmt.Errorf("failed to read from world state: %v", err)
	}
	if userJSON == nil {
		return nil, fmt.Errorf("user %s does not exist", id)
	}
	var user User
	err = json.Unmarshal(userJSON, &user)
	return &user, err
}

func (s *SmartContract) UserExists(ctx contractapi.TransactionContextInterface, id string) (bool, error) {
	userJSON, err := ctx.GetStub().GetState(id)
	if err != nil {
		return false, err
	}
	return userJSON != nil, nil
}

func (s *SmartContract) updateUser(ctx contractapi.TransactionContextInterface, user *User) error {
	userJSON, err := json.Marshal(user)
	if err != nil {
		return err
	}
	return ctx.GetStub().PutState(user.ID, userJSON)
}

func (s *SmartContract) RevokeUser(ctx contractapi.TransactionContextInterface, id string) {
	user, err := s.GetUser(ctx, id)
	if err != nil {
		return
	}
	user.Revoked = true
	user.InterregionalAuthenticated = false
	_ = s.updateUser(ctx, user)
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
		return errors.New("certificate expired or not valid")
	}
	return nil
}

func verifyCertSignedByTrustedCA(certPem string) error {
	userCert, err := parseCertificate(certPem)
	if err != nil {
		return err
	}
	caCert, err := parseCertificate(trustedCACertPEM)
	if err != nil {
		return err
	}
	if err := userCert.CheckSignatureFrom(caCert); err != nil {
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

