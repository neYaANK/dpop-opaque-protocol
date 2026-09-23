# OPAQUE + DPoP Proof of Concept (PoC)

An integrated cryptographic authentication and authorization Proof of Concept combining the **OPAQUE protocol (RFC 9892)** with **Demonstrating Proof-of-Possession (DPoP, RFC 9449)** for modern applications.

Developed as part of a Bachelor's Thesis in Computer Science at TU Wien.

---
## Start
![alt text](OPAQUE_DPOP_DEMO.png "Demo screenshot")
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
```
---
### DPoP
#### **Init**
1. Client generates public-private keypair

#### **Binding**
1. Client creates JWT DPoP-Proof with JWK, signs it with private key and sends it to the Server
2. Server reads public key and checks correctness of the DPoP-Proof Signature
3. Server calculates JKT from obtained JWK (SHA256 the JWK and encode as Base64 URL) 
4. Server mints an access token with JKT embedded inside of it and returns it to the client.

#### **Accessing resources**
1. Client generates JWT DPoP-Proof with HTTP method, url and hash of the access token
2. Client requests specified resource with access token and DPoP-Proof in headers
3. Server takes JWK from DPoP-Proof and calculates JKT
4. Server compares calculated JKT with JKT in access token
5. Server verifies JWT signature of DPoP-Proof with extracted JWK
6. Server verifies metadata (HTTP method, Url, ...)
7. If everything is fine, the request succeedes


```mermaid
sequenceDiagram
    autonumber
    actor Client
    participant Server

    rect rgb(84, 140, 138, 1)
    Note over Client: INIT
    Note over Client: Generate asymmetric keypair (e.g. P-256):<br/>1. privateKey: kept non-extractable in WebCrypto<br/>2. publicKey: represented as JWK {kty: EC, crv: P-256, x: ..., y: ...}
    end

    rect rgb(84, 140, 138, 1)
    Note over Client, Server: DPoP TOKEN REQUEST

    Note over Client: Build DPoP Proof:<br/>JOSE Header:<br/>  typ: 'dpop+jwt', alg: 'ES256', jwk: {publicKey}<br/>JWT Payload:<br/>  jti: random_uuid()<br/>  htm: 'POST'<br/>  htu: 'https://auth.example.com/oauth/token'<br/>  iat: current_timestamp()<br/>Sign JWT using privateKey

    Client->>Server: POST /oauth/token<br/>Header: DPoP: <DPoP_Proof_JWT_1>

    Note over Server: Validate Proof:<br/>1. Check header.typ == 'dpop+jwt'<br/>2. Extract proof.header.jwk<br/>3. Verify signature of Proof using proof.header.jwk <br/>4. Validate payload: htm == 'POST', htu matches URL, iat is fresh<br/>5. Check jti was not seen before

    Note over Server: Mint DPoP-Bound Access Token:<br/>1. Calculate thumbprint: JKT = Base64URL(SHA-256(canonical(jwk)))<br/>2. Create Access Token (JWT):<br/>   Header: { typ: 'jwt', alg: 'RS256' }<br/>   Payload: { sub: 'user123', cnf: { jkt: JKT }, exp: ..., ... }<br/>3. Sign Token with Server Private Key

    Server-->>Client: HTTP 200 OK<br/>Body: { access_token: 'ey...', token_type: 'DPoP', expires_in: 3600 }
    end

    rect rgb(84, 140, 138, 1)
    Note over Client, Server: PROTECTED ACCESS

    Note over Client: 1. Bind proof to token: ath = Base64URL(SHA-256(access_token))<br/>2. Build DPoP Proof:<br/>   Header: { typ: 'dpop+jwt', alg: 'ES256', jwk: publicKey }<br/>   Payload: { jti, htm: 'GET', htu: '/resource/1', iat, ath }<br/>3. Sign Proof with client privateKey

    Client->>Server: GET /resource/1<br/>Header: Authorization: DPoP <access_token><br/>Header: DPoP: <DPoP_Proof_JWT_2>

    Note over Server: Validate Access Token<br/>1. Verify server signature & exp on access_token<br/>2. Extract expected_jkt from access_token.payload.cnf.jkt

    Note over Server: Validate DPoP Proof<br/>1. Extract client_jwk from proof.header<br/>2. Verify Proof signature with client_jwk<br/>3. Verify: Base64URL(SHA-256(client_jwk)) == expected_jkt

    Note over Server: Validate Request Context<br/>1. Check htm == 'GET' and htu == '/resource/1'<br/>2. Check Base64URL(SHA-256(received_token)) == proof.payload.ath<br/>3. Check jti replay cache 

    Server-->>Client: HTTP 200 OK<br/>Body: { user_id: 'user123', email: '...', data: '...' }
    end
```
---
### OPAQUE
G - specification constant point at elliptic curve
#### **OPRF**
1. Client transforms password to a point at elliptic curve
2. Then multiplies this point with random generated value R and sends to the server
3. Server then multiplies the point with its key value (also randomly generated, but only once and is the same for all) and returns it to the client
4. Client reverses the multiplication with value R and obtains password multiplied with server key.

#### **Registration:**

1. OPRF
2. Generates symmetric key SK based on the OPRF response
3. Client generates new pubclic-private keypair and encrypts private key with AES and symmetric key SK
4. Client sends encrypted private key and not encrypted public key to the server and this pair is saved (later Envelope)

#### **Login**

1. OPRF
2. Generates symmetric key SK based on the OPRF response
3. Client also sends G * ec (Client Random Value)
3. Server also returns Envelope for specified user and G * es (Server Random Value)
4. Obtain private key from Envelop by decrpyting it with obtained symmetric key (always the same)
5. 3DH (Client Random Value and Server Random Value, clienKey, serverKey): 
    1. DH1 Client: ec * G * es; DH1 Server: es * G * ec; DH1C=DH1S; ec * G * es = es * G * ec.
    2. DH2 Client: privateClientKey * es * G; DH2 Server: es * publicClientKey = es * G * privateClientKey;
    3. DH3 Client: ec * publicServerKey = ec * privateServerKey * G; DH3 Server = privateServerKey * G * ec
6. Use HKDF to generate Client MAC Key, Server MAC Key and Session Key on both client and server
7. Server signs all preceeding communication data with Server Key and sends to the client.
8. Client performs the same calculation and compares server data. If they are same, then server is valid.
9. Repeat the same process with Client MAC Key, thus proofing that Client is valid.
10. Both Client and Server proofed that they calculated correct keys. Now Session key is considered valid and can be used for communication.

```mermaid
sequenceDiagram
    autonumber
    actor Client
    participant Server

    rect rgba(84, 140, 138, 1)
    Note over Client, Server: REGISTRATION FLOW

    Note over Client: 1. Point = HashToCurve(Password)<br/>2. Generate random value R <br/>3. Blinded = R * Point
    Client->>Server: Send Blinded Point (Random * Point)
    Note over Server: Evaluated = ServerKey * Blinded
    Server-->>Client: Return Evaluated Point
    Note over Client: Unblind: OPRF_Result = Evaluated * (1/R)

    Note over Client: Derive symmetric key SK from OPRF_Result<br/>Generate keypair (privateClientKey, publicClientKey)<br/>EncryptedPrivKey = AES_Encrypt(SK, privateClientKey)
    Client->>Server: Send Envelope (EncryptedPrivKey, publicClientKey)
    Note over Server: Store Envelope for User
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
    Client->>Server: Send ClientMAC
    Note over Server: Verify ClientMAC with local ClientMACKey

    Note over Client, Server: SessionKey is established
    end


```


---