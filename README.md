# OPAQUE + DPoP Proof of Concept (PoC)

An integrated cryptographic authentication and authorization Proof of Concept combining the **OPAQUE protocol (RFC 9892)** with **Demonstrating Proof-of-Possession (DPoP, RFC 9449)** for modern applications.

Developed as part of a Bachelor's Thesis in Computer Science at TU Wien.

---
## Start
To start the application, run
```
cd dpop-opaque-protocol
npm install
npm start
```
---
## Overview

Traditional Web applications often suffer from fundamental security issues:
- Passwords sent over the network as a clear text (even over TLS) or stored as hashes are susceptible to server-side database compromise, offline dictionary attacks, and credential stuffing.
- Standard OAuth 2.0 Bearer tokens are bearer credentials: if intercepted via XSS, network eavesdropping, or server logging, an attacker can reuse them directly.

This project demonstrates a zero-knowledge, password-authenticated architecture combined with cryptographically bound access tokens:
- **Asymmetric PAKE (OPAQUE):** The server never learns the user's password, and no password hashes are stored in the database. Client and server mutually authenticate each other using an Oblivious Pseudorandom Function (OPRF) and a 3-way Diffie-Hellman handshake (3DH).
- **Constrained Tokens (DPoP):** Upon successful OPAQUE login, the Server binds the minted JWT Access Token to a non-extractable asymmetric key generated via WebCrypto on the client. 
- **Protected Resource Access:** Every API request requires a short-lived, signed DPoP-Proof cross-bound to the access token and HTTP method/URI, preventing token hijacking and replay attacks.

---

### Integrated OPAQUE Login & DPoP Binding Flow
During the final phase of OPAQUE authentication, the client completes the mutual handshake by computing the `ClientMAC` over the session transcript. Simultaneously, the client signs a DPoP Proof containing its public JWK. The server validates both the credentials and the proof, computes the canonical JWK Thumbprint (`cnf.jkt`), and issues a bound Access Token.

```mermaid
sequenceDiagram
    autonumber
    actor Client
    participant Server

    rect rgb(84, 140, 138, 1)
    Note over Client: CLIENT INIT
    Note over Client: Generate asymmetric keypair (e.g. P-256):<br/>1. privateKey: kept non-extractable in WebCrypto<br/>2. publicKey: represented as JWK {kty: EC, crv: P-256, x: ..., y: ...}
    end

    rect rgb(84, 140, 138, 1)

    Note over Client, Server: LOGIN FLOW

Note over Client: 1. Point = HashToCurve(Password)<br/>2. Blinded = Random * Point<br/>3. Generate random ec, G - curve point <br/>4. EClient = ec * G
    Client->>Server: Send (Blinded Point, EClient)
    
    Note over Server: 1. Evaluated = ServerKey * Blinded<br/>2. Generate random es, EServer = es * G<br/>3. Fetch User Envelope
    
    Note over Server: Compute 3DH:<br/>DH1 = es * EClient<br/>DH2 = es * publicClientKey<br/>DH3 = privateServerKey * EClient
    Note over Server: Derive ClientMACKey, ServerMACKey, SessionKey <br/>with HKDF(DH1, DH2, DH3) 
    Note over Server: ServerMAC = MAC(ServerMACKey, Transcript)
    Server-->>Client: Return (Evaluated, EServer, Envelope, ServerMAC)

    Note over Client: 1. Unblind OPRF_Result and derive SK<br/>2. privateClientKey = AES_Decrypt(SK, EncryptedPrivKey)<br/>3. Compute 3DH (Triple Diffie-Hellman):<br/>DH1 = ec * EServer<br/>DH2 = privateClientKey * EServer<br/>DH3 = ec * publicServerKey
    Note over Client: Derive ClientMACKey, ServerMACKey, SessionKey <br/>with HKDF(DH1, DH2, DH3) 
    Note over Client: Verify ServerMAC sent by server
    Note over Client: ClientMAC = MAC(ClientMACKey, Transcript)

    Note over Client: Build DPoP Proof<br/>Sign JWT using privateKey    
    
    Client->>Server: Send ClientMAC, Header: DPoP <DPoP_Proof_JWT>

    Note over Server: Verify ClientMAC with local ClientMACKey
    Note over Server: Validate Proof
    Note over Server: Mint DPoP-Bound Access Token
    Server-->>Client: Return { access_token: 'ey...', token_type: 'DPoP', expires_in: 3600 }
    
    end