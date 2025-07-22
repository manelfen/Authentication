# IoT Authentication System with Hyperledger Fabric

This project provides a secure authentication system for IoT devices using Hyperledger Fabric. It includes multi-level verification, device-to-device mutual authentication, and secure certificate-based identity management.

##  About the Project

1. 🔐 **Mutual Authentication Between IoT Devices**  
   Devices validate each other using signed certificates and digital signatures before communication.

2. 🏷️ **Unique and Traceable Identity for Each Device**  
   Every device is securely registered and identified on the blockchain ledger.

3. 🌍 **Multi-Level Authentication Architecture**  
   Authentication is handled at local, regional, and inter-regional levels using different smart contracts.

4. 📦 **Smart Contracts Written in Go for Hyperledger Fabric**  
   Separate contracts manage registration, authentication, and logging of security events.

5. 🧠 **Blockchain-Based Logging for Critical Events**  
   All actions (e.g., registration, authentication) are immutably recorded for transparency and auditing.

6. ⚙️ **Secure Express.js Server with HTTPS  **  
   Devices connect to the server over TLS, and authenticated sessions are managed.

8. 🧪 **Tested Scenarios Include Signature Verification and Timestamp Validation**  
   The system ensures each device's certificate is valid and its authentication signature is legitimate and timely.


