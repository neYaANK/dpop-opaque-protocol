# OPAQUE + DPoP Proof of Concept (PoC)

An integrated cryptographic authentication and authorization Proof of Concept combining the **OPAQUE protocol (RFC 9892)** with **Demonstrating Proof-of-Possession (DPoP, RFC 9449)** for modern single-page applications.

Developed as part of a Bachelor's Thesis in Computer Science at TU Wien.

---

## Overview

Traditional Web applications often suffer from fundamental security tradeoffs:
- Passwords sent over the network (even over TLS) or stored as hashes are susceptible to server-side database compromise, offline dictionary attacks, and credential stuffing.
- Standard OAuth 2.0 Bearer tokens are bearer credentials: if intercepted via XSS, network eavesdropping, or server logging, an attacker can reuse them directly.

This project demonstrates a zero-knowledge, password-authenticated architecture combined with cryptographically bound access tokens:
1. **Asymmetric PAKE (OPAQUE):** The server never learns the user's password, and no password hashes are stored in the database. Client and server mutually authenticate each other using an Oblivious Pseudorandom Function (OPRF) and a 3-way Diffie-Hellman handshake (3DH).
2. **Constrained Tokens (DPoP):** Upon successful OPAQUE login, the Server binds the minted JWT Access Token to a non-extractable asymmetric key generated via WebCrypto on the client. 
3. **Protected Resource Access:** Every API request requires a short-lived, signed `DPoP-Proof` cross-bound to the access token (`ath`) and HTTP method/URI (`htm`, `htu`), preventing token hijacking and replay attacks.

---

## Protocols

### 1. Integrated OPAQUE Login & DPoP Binding Flow
During the final phase of OPAQUE authentication (`finishLogin`), the client completes the mutual handshake by computing the `ClientMAC` over the session transcript. Simultaneously, the client signs a DPoP Proof containing its public JWK. The server validates both the credentials and the proof, computes the canonical JWK Thumbprint (`cnf.jkt`), and issues a bound Access Token.

```mermaid
sequenceDiagram
    autonumber
    actor Client
    participant Server

    rect rgb(84, 140, 138)
    Note over Client: CLIENT INIT
    Note over Client: Generate asymmetric keypair (WebCrypto, non-extractable P-256):<br/>- privateKey: kept in browser memory<br/>- publicKey: represented as JWK
    end

    rect rgb(48, 48, 48)
    Note over Client, Server: LOGIN ROUND 1 (START)
    Note over Client: OPRF blinding: PwdPoint = HashToCurve(Password)<br/>Blinded = R * PwdPoint, EphemeralClient = ec * G
    Client->>Server: POST /api/login/start (Blinded, EphemeralClient)
    Note over Server: Evaluated = ServerKey * Blinded, EphemeralServer = es * G<br/>Compute 3DH & derive keys via HKDF<br/>ServerMAC = MAC(ServerMACKey, Transcript1)
    Server-->>Client: HTTP 200 (Evaluated, EphemeralServer, Envelope, ServerMAC)
    end

    rect rgb(60, 60, 60)
    Note over Client, Server: LOGIN ROUND 2 + DPoP BINDING (FINISH)
    Note over Client: Unblind OPRF -> Recover SK -> Decrypt Envelope<br/>Compute 3DH & verify ServerMAC<br/>Compute ClientMAC = MAC(ClientMACKey, Transcript2)<br/>Sign DPoP-Proof JWT with privateKey (includes JWK in header)
    Client->>Server: POST /api/login/finish<br/>Header: DPoP: <DPoP_Proof_JWT><br/>Body: { clientMac: ClientMAC }
    Note over Server: Verify ClientMAC (User Authenticated)<br/>Validate DPoP-Proof signature using proof.header.jwk<br/>Calculate Thumbprint: JKT = Base64URL(SHA-256(canonical(jwk)))<br/>Mint JWT Access Token with cnf: { jkt: JKT }
    Server-->>Client: HTTP 200 { access_token, token_type: "DPoP" }
    end