import { Injectable, signal } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import * as opaque from '@serenity-kit/opaque';
import { firstValueFrom } from 'rxjs';
import { environment } from '../../../environments/environment';
import { AuthStrategy } from '../auth-strategy.interface';
import {
  AuthResult,
  DPoPOpaqueRegisterStartRequest,
  DPoPOpaqueRegisterStartResponse,
  DPoPOpaqueRegisterFinishRequest,
  DPoPOpaqueRegisterFinishResponse,
  DPoPOpaqueLoginStartRequest,
  DPoPOpaqueLoginStartResponse,
  DPoPOpaqueLoginFinishRequest,
  DPoPOpaqueLoginFinishResponse,
  DPoPOpaqueProtectedGetResponse,
  DPoPOpaqueProtectedPostResponse,
} from '../auth.types';
import { ProtocolLoggerService } from '../logger.service';

function base64UrlEncode(buffer: ArrayBuffer | Uint8Array | string): string {
  let str = '';
  if (typeof buffer === 'string') {
    str = btoa(unescape(encodeURIComponent(buffer)));
  } else {
    const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    for (let i = 0; i < bytes.byteLength; i++) {
      str += String.fromCharCode(bytes[i]);
    }
    str = btoa(str);
  }
  return str.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64UrlDecodeJson(b64url: string): any {
  try {
    let base64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
    while (base64.length % 4) {
      base64 += '=';
    }
    return JSON.parse(decodeURIComponent(escape(atob(base64))));
  } catch {
    return { raw: b64url };
  }
}

async function computeJkt(jwk: any): Promise<string> {
  const canonical = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y });
  const hashBuffer = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(canonical));
  return base64UrlEncode(hashBuffer);
}

@Injectable({
  providedIn: 'root',
})
export class DPoPOpaqueStrategy implements AuthStrategy {
  readonly id = 'dpop-opaque' as const;
  readonly name = 'DPoP + OPAQUE';
  readonly description =
    'Combines OPAQUE zero-knowledge password authentication with DPoP asymmetric Proof-of-Possession request binding.';

  private readonly BASE_URL = `${environment.apiUrl}/dpop-opaque`;
  private readonly REGISTER_START_URL = `${this.BASE_URL}/register/start`;
  private readonly REGISTER_FINISH_URL = `${this.BASE_URL}/register/finish`;
  private readonly LOGIN_START_URL = `${this.BASE_URL}/login/start`;
  private readonly LOGIN_FINISH_URL = `${this.BASE_URL}/login/finish`;
  private readonly PROTECTED_URL = `${this.BASE_URL}/protected/data`;

  private keyPair: CryptoKeyPair | null = null;
  private jwk: any | null = null;

  readonly activeToken = signal<string | null>(null);
  readonly activeSessionKey = signal<string | null>(null);
  readonly activeUsername = signal<string | null>(null);
  readonly activeAccessToken = signal<string | null>(null);

  constructor(
    private http: HttpClient,
    private logger: ProtocolLoggerService
  ) {}

  reset() {
    this.keyPair = null;
    this.jwk = null;
    this.activeToken.set(null);
    this.activeSessionKey.set(null);
    this.activeUsername.set(null);
    this.activeAccessToken.set(null);
  }

  private async ensureKeyPair(): Promise<{ keyPair: CryptoKeyPair; jwk: any; }> {
    if (this.keyPair && this.jwk) {
      return { keyPair: this.keyPair, jwk: this.jwk };
    }

    this.logger.addLog({
      actor: 'Client',
      step: 'WebCrypto: Generate ECDSA KeyPair',
      description: 'Client generates asymmetric ECDSA P-256 key pair via Web Crypto API for DPoP proof generation.',
      status: 'info',
    });

    const keyPair = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify']
    );

    const fullJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
    const jwk = { kty: fullJwk.kty, crv: fullJwk.crv, x: fullJwk.x, y: fullJwk.y };
    const jkt = await computeJkt(jwk);

    this.keyPair = keyPair;
    this.jwk = jwk;
   

    this.logger.addLog({
      actor: 'Client',
      step: 'WebCrypto: Public JWK & Thumbprint (JKT)',
      description: 'Exported public JWK and calculated canonical SHA-256 thumbprint (jkt).',
      crypto: { publicJwk: jwk, calculatedJktThumbprint: jkt },
      status: 'info',
    });

    return { keyPair, jwk };
  }

  private async createDPoPProof(method: string, url: string, accessToken?: string): Promise<string> {
    const { keyPair, jwk } = await this.ensureKeyPair();

    const header = {
      typ: 'dpop+jwt',
      alg: 'ES256',
      jwk,
    };

    const payload: any = {
      jti: crypto.randomUUID(),
      htm: method.toUpperCase(),
      htu: url,
      iat: Math.floor(Date.now() / 1000),
    };

    if (accessToken) {
      const hashBuffer = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(accessToken));
      payload.ath = base64UrlEncode(hashBuffer);
    }

    const headerB64 = base64UrlEncode(JSON.stringify(header));
    const payloadB64 = base64UrlEncode(JSON.stringify(payload));
    const signingInput = `${headerB64}.${payloadB64}`;

    const signatureBuffer = await crypto.subtle.sign(
      { name: 'ECDSA', hash: { name: 'SHA-256' } },
      keyPair.privateKey,
      new TextEncoder().encode(signingInput)
    );

    const signatureB64 = base64UrlEncode(signatureBuffer);
    return `${signingInput}.${signatureB64}`;
  }

  async register(username: string, password: string): Promise<AuthResult> {
    await opaque.ready;

    const { clientRegistrationState, registrationRequest } = opaque.client.startRegistration({
      password,
    });

    this.logger.addLog({
      actor: 'Client',
      step: '1. opaque.client.startRegistration',
      description: 'Client starts registration: locally generates a blinded registrationRequest. Password never leaves browser!',
      crypto: { registrationRequest, clientRegistrationState },
      status: 'info',
    });

    const startPayload: DPoPOpaqueRegisterStartRequest = { username, registrationRequest };
    this.logger.addLog({
      actor: 'Network',
      step: '2. POST /api/dpop-opaque/register/start',
      description: 'Client transmits username and blinded registrationRequest to server.',
      body: startPayload,
      status: 'info',
    });

    let startResponse: DPoPOpaqueRegisterStartResponse;
    try {
      startResponse = await firstValueFrom(
        this.http.post<DPoPOpaqueRegisterStartResponse>(this.REGISTER_START_URL, startPayload)
      );
    } catch (err: any) {
      this.logger.addLog({
        actor: 'Server',
        step: 'Error /api/dpop-opaque/register/start',
        description: `Server returned error: ${err?.error?.error || err.message}`,
        details: err?.error || { message: err.message },
        status: 'error',
      });
      throw err;
    }

    this.logger.addLog({
      actor: 'Server',
      step: '3. Response from /api/dpop-opaque/register/start',
      description: 'Server computed registrationResponse using serverSetup private key.',
      body: startResponse,
      status: 'info',
    });

    const { registrationRecord, exportKey, serverStaticPublicKey } =
      opaque.client.finishRegistration({
        clientRegistrationState,
        registrationResponse: startResponse.registrationResponse,
        password,
      });

    this.logger.addLog({
      actor: 'Client',
      step: '4. opaque.client.finishRegistration (Output)',
      description: 'Client computes encrypted registrationRecord envelope, client-only exportKey, and serverStaticPublicKey.',
      crypto: { registrationRecord, exportKey, serverStaticPublicKey },
      status: 'info',
    });

    const finishPayload: DPoPOpaqueRegisterFinishRequest = { username, registrationRecord };
    this.logger.addLog({
      actor: 'Network',
      step: '5. POST /api/dpop-opaque/register/finish',
      description: 'Client sends registrationRecord to server for persistent storage.',
      body: finishPayload,
      status: 'info',
    });

    let finishResponse: DPoPOpaqueRegisterFinishResponse;
    try {
      finishResponse = await firstValueFrom(
        this.http.post<DPoPOpaqueRegisterFinishResponse>(this.REGISTER_FINISH_URL, finishPayload)
      );
    } catch (err: any) {
      this.logger.addLog({
        actor: 'Server',
        step: 'Error /api/dpop-opaque/register/finish',
        description: `Server returned error: ${err?.error?.error || err.message}`,
        details: err?.error || { message: err.message },
        status: 'error',
      });
      throw err;
    }

    this.logger.addLog({
      actor: 'Server',
      step: '6. Response from /api/dpop-opaque/register/finish',
      description: 'Server stored registrationRecord in users.json. Password was never exposed!',
      body: finishResponse,
      status: 'success',
    });

    return {
      success: finishResponse.success,
      message: finishResponse.message,
      exportKey,
      serverStaticPublicKey,
    };
  }

  async login(username: string, password: string): Promise<AuthResult> {
    await opaque.ready;

    const { clientLoginState, startLoginRequest } = opaque.client.startLogin({
      password,
    });

    this.logger.addLog({
      actor: 'Client',
      step: '1. opaque.client.startLogin',
      description: 'Client generates blinded startLoginRequest and saves clientLoginState.',
      crypto: { startLoginRequest, clientLoginState },
      status: 'info',
    });

    const startPayload: DPoPOpaqueLoginStartRequest = { username, startLoginRequest };
    this.logger.addLog({
      actor: 'Network',
      step: '2. POST /api/dpop-opaque/login/start',
      description: 'Client sends username and startLoginRequest to server.',
      body: startPayload,
      status: 'info',
    });

    let startResponse: DPoPOpaqueLoginStartResponse;
    try {
      startResponse = await firstValueFrom(
        this.http.post<DPoPOpaqueLoginStartResponse>(
          this.LOGIN_START_URL,
          startPayload
        )
      );
    } catch (err: any) {
      this.logger.addLog({
        actor: 'Server',
        step: 'Error /api/dpop-opaque/login/start',
        description: `Server error: ${err?.error?.error || err.message}`,
        details: err?.error || { message: err.message },
        status: 'error',
      });
      throw err;
    }

    this.logger.addLog({
      actor: 'Server',
      step: '3. Response from /api/dpop-opaque/login/start',
      description: 'Server computed loginResponse and stored serverLoginState in temporary session.',
      body: startResponse,
      status: 'info',
    });

    let clientLoginResult: any;
    try {
      clientLoginResult = opaque.client.finishLogin({
        clientLoginState,
        loginResponse: startResponse.loginResponse,
        password,
      });
    } catch (err: any) {
      this.logger.addLog({
        actor: 'Client',
        step: 'Error opaque.client.finishLogin',
        description: 'Incorrect password! Envelope could not be decrypted.',
        details: { error: err.message },
        status: 'error',
      });
      throw err;
    }

    if (!clientLoginResult) {
      throw new Error('Client login failed: invalid password or corrupted credentials');
    }

    const { finishLoginRequest, sessionKey: clientSessionKey, exportKey, serverStaticPublicKey } =
      clientLoginResult;

    this.logger.addLog({
      actor: 'Client',
      step: '4. opaque.client.finishLogin',
      description: 'Client attempts to unlock envelope using password. Computes sessionKey and finishLoginRequest proof.',
      crypto: { finishLoginRequest, clientSessionKey, exportKey, serverStaticPublicKey },
      status: 'info',
    });

    const dpopProof = await this.createDPoPProof('POST', this.LOGIN_FINISH_URL);
    this.logger.addLog({
      actor: 'Client',
      step: '4b. Generate DPoP Login Proof (JWT)',
      description: 'Client signed a DPoP proof JWT with private ECDSA key for login completion.',
      crypto: {
        dpopProofJwtHeader: base64UrlDecodeJson(dpopProof.split('.')[0]),
        dpopProofJwtPayload: base64UrlDecodeJson(dpopProof.split('.')[1]),
        rawDPoPProof: dpopProof,
      },
      status: 'info',
    });

    const finishPayload: DPoPOpaqueLoginFinishRequest = {
      loginSessionId: startResponse.loginSessionId,
      finishLoginRequest,
    };
    this.logger.addLog({
      actor: 'Network',
      step: '5. POST /api/dpop-opaque/login/finish with DPoP Header',
      description: 'Client sends finishLoginRequest proof, loginSessionId, and DPoP proof header.',
      headers: {
        'DPoP': dpopProof,
      },
      body: finishPayload,
      status: 'info',
    });

    let finishResponse: DPoPOpaqueLoginFinishResponse;
    try {
      finishResponse = await firstValueFrom(
        this.http.post<DPoPOpaqueLoginFinishResponse>(
          this.LOGIN_FINISH_URL,
          finishPayload,
          { headers: { DPoP: dpopProof } }
        )
      );
    } catch (err: any) {
      this.logger.addLog({
        actor: 'Server',
        step: 'Error /api/dpop-opaque/login/finish',
        description: `Server rejected proof: ${err?.error?.error || err.message}`,
        details: err?.error || { message: err.message },
        status: 'error',
      });
      throw err;
    }

    const decodedToken = base64UrlDecodeJson(finishResponse.accessToken.split('.')[1]);

    this.logger.addLog({
      actor: 'Server',
      step: '6. Response from /api/dpop-opaque/login/finish',
      description: 'Server verified OPAQUE proof & DPoP signature. Issued bound access token with embedded cnf.jkt!',
      body: finishResponse,
      crypto: {
        clientSessionKey,
        issuedAccessToken: finishResponse.accessToken,
        decodedTokenPayload: decodedToken,
        embeddedCnfJkt: decodedToken?.cnf?.jkt,
      },
      status: 'success',
    });

    this.activeSessionKey.set(clientSessionKey);
    this.activeUsername.set(finishResponse.username);
    this.activeAccessToken.set(finishResponse.accessToken);
    this.activeToken.set(finishResponse.accessToken);

    const { jwk } = await this.ensureKeyPair();
    const jkt = await computeJkt(jwk);

    return {
      success: finishResponse.success,
      message: finishResponse.message,
      username: finishResponse.username,
      sessionKey: clientSessionKey,
      accessToken: finishResponse.accessToken,
      dpopThumbprint: jkt,
      exportKey,
      serverStaticPublicKey,
    };
  }

  async testProtectedGet(): Promise<DPoPOpaqueProtectedGetResponse> {
    const token = this.activeAccessToken();
    if (!token) {
      throw new Error('Please login first using DPoP + OPAQUE to obtain an active access token.');
    }

    const dpopProof = await this.createDPoPProof('GET', this.PROTECTED_URL, token);

    this.logger.addLog({
      actor: 'Client',
      step: '1. Generate DPoP Proof for Protected GET',
      description: 'Client signed a fresh single-use DPoP proof JWT with ath claim for GET endpoint.',
      crypto: {
        dpopProofJwtHeader: base64UrlDecodeJson(dpopProof.split('.')[0]),
        dpopProofJwtPayload: base64UrlDecodeJson(dpopProof.split('.')[1]),
        rawDPoPProof: dpopProof,
      },
      status: 'info',
    });

    this.logger.addLog({
      actor: 'Network',
      step: '2. GET /api/dpop-opaque/protected/data with Headers',
      description: 'Client sends Authorization and DPoP headers.',
      headers: {
        'Authorization': `DPoP ${token}`,
        'DPoP': dpopProof,
      },
      status: 'info',
    });

    try {
      const response = await firstValueFrom(
        this.http.get<DPoPOpaqueProtectedGetResponse>(this.PROTECTED_URL, {
          headers: {
            Authorization: `DPoP ${token}`,
            DPoP: dpopProof,
          },
        })
      );

      this.logger.addLog({
        actor: 'Server',
        step: '3. Protected GET Response',
        description: 'Server verified Proof-of-Possession and granted access to confidential resource.',
        status: 'success',
      });

      return response;
    } catch (err: any) {
      this.logger.addLog({
        actor: 'Server',
        step: 'Protected GET Failed',
        description: `Server rejected request: ${err?.error?.error || err.message}`,
        details: err?.error || { message: err.message },
        status: 'error',
      });
      throw err;
    }
  }

  async testProtectedPost(payload: any): Promise<DPoPOpaqueProtectedPostResponse> {
    const token = this.activeAccessToken();
    if (!token) {
      throw new Error('Please login first using DPoP + OPAQUE to obtain an active access token.');
    }

    const dpopProof = await this.createDPoPProof('POST', this.PROTECTED_URL, token);

    this.logger.addLog({
      actor: 'Client',
      step: '1. Generate DPoP Proof for Protected POST',
      description: 'Client signed a fresh single-use DPoP proof JWT with ath claim for POST endpoint.',
      crypto: {
        dpopProofJwtHeader: base64UrlDecodeJson(dpopProof.split('.')[0]),
        dpopProofJwtPayload: base64UrlDecodeJson(dpopProof.split('.')[1]),
        rawDPoPProof: dpopProof,
      },
      status: 'info',
    });

    this.logger.addLog({
      actor: 'Network',
      step: '2. POST /api/dpop-opaque/protected/data with Headers',
      description: 'Client sends Authorization and DPoP proof headers.',
      headers: {
        'Authorization': `DPoP ${token}`,
        'DPoP': dpopProof,
      },
      status: 'info',
    });

    try {
      const response = await firstValueFrom(
        this.http.post<DPoPOpaqueProtectedPostResponse>(this.PROTECTED_URL, payload, {
          headers: {
            Authorization: `DPoP ${token}`,
            DPoP: dpopProof,
          },
        })
      );

      this.logger.addLog({
        actor: 'Server',
        step: '3. Protected POST Response',
        description: 'Server verified Proof-of-Possession and processed POST data successfully.',
        status: 'success',
      });

      return response;
    } catch (err: any) {
      this.logger.addLog({
        actor: 'Server',
        step: 'Protected POST Failed',
        description: `Server rejected POST request: ${err?.error?.error || err.message}`,
        details: err?.error || { message: err.message },
        status: 'error',
      });
      throw err;
    }
  }
}
