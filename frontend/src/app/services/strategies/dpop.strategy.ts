import { Injectable, signal } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { firstValueFrom } from 'rxjs';
import { environment } from '../../../environments/environment';
import { AuthStrategy } from '../auth-strategy.interface';
import {
  AuthResult,
  ProtectedResponse,
  DPoPRegisterRequest,
  DPoPRegisterResponse,
  DPoPLoginRequest,
  DPoPLoginResponse,
  DPoPProtectedGetResponse,
  DPoPProtectedPostResponse,
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
export class DPoPStrategy implements AuthStrategy {
  readonly id = 'dpop' as const;
  readonly name = 'DPoP';
  readonly description =
    'Demonstrating Proof-of-Possession. Access tokens are bound to client.';

  private readonly BASE_URL = `${environment.apiUrl}/dpop`;
  private readonly REGISTER_URL = `${this.BASE_URL}/register`;
  private readonly LOGIN_URL = `${this.BASE_URL}/login`;
  private readonly PROTECTED_URL = `${this.BASE_URL}/protected/data`;

  private keyPair: CryptoKeyPair | null = null;
  private jwk: any | null = null;

  readonly activeToken = signal<string | null>(null);
  readonly activeUsername = signal<string | null>(null);

  constructor(
    private http: HttpClient,
    private logger: ProtocolLoggerService
  ) {}

  reset() {
    this.keyPair = null;
    this.jwk = null;
    this.activeToken.set(null);
    this.activeUsername.set(null);
  }

  private async ensureKeyPair(): Promise<{ keyPair: CryptoKeyPair; jwk: any; }> {
    if (this.keyPair && this.jwk ) {
      return { keyPair: this.keyPair, jwk: this.jwk};
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

    return { keyPair, jwk};
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
    const payload: DPoPRegisterRequest = { username, password };
    this.logger.addLog({
      actor: 'Network',
      step: '1. POST /api/dpop/register',
      description: 'Client sends registration credentials to DPoP register endpoint.',
      body: payload,
      status: 'info',
    });

    try {
      const response = await firstValueFrom(
        this.http.post<DPoPRegisterResponse>(this.REGISTER_URL, payload)
      );

      this.logger.addLog({
        actor: 'Server',
        step: '2. Response from /api/dpop/register',
        description: 'Server registered user credentials for DPoP authentication.',
        body: response,
        status: 'success',
      });

      return {
        success: response.success,
        message: response.message,
      };
    } catch (err: any) {
      this.logger.addLog({
        actor: 'Server',
        step: 'Error /api/dpop/register',
        description: `Registration error: ${err?.error?.error || err.message}`,
        details: err?.error || { message: err.message },
        status: 'error',
      });
      throw err;
    }
  }

  async login(username: string, password: string): Promise<AuthResult> {
    const dpopProof = await this.createDPoPProof('POST', this.LOGIN_URL);

    this.logger.addLog({
      actor: 'Client',
      step: '1. Generate DPoP Login Proof (JWT)',
      description: 'Client signed a DPoP proof JWT with private ECDSA key for login request.',
      crypto: {
        dpopProofJwtHeader: base64UrlDecodeJson(dpopProof.split('.')[0]),
        dpopProofJwtPayload: base64UrlDecodeJson(dpopProof.split('.')[1]),
        rawDPoPProof: dpopProof,
      },
      status: 'info',
    });

    const payload: DPoPLoginRequest = { username, password };
    this.logger.addLog({
      actor: 'Network',
      step: '2. POST /api/dpop/login with DPoP Header',
      description: 'Client sends credentials and DPoP proof header to server.',
      headers: {
        'DPoP': dpopProof,
      },
      body: payload,
      status: 'info',
    });

    try {
      const response = await firstValueFrom(
        this.http.post<DPoPLoginResponse>(
          this.LOGIN_URL,
          payload,
          { headers: { DPoP: dpopProof } }
        )
      );

      const decodedToken = base64UrlDecodeJson(response.accessToken.split('.')[1]);

      this.logger.addLog({
        actor: 'Server',
        step: '3. DPoP Login Verified',
        description: 'Server validated credentials and DPoP signature. Issued access token with embedded cnf.jkt!',
        body: response,
        crypto: {
          issuedAccessToken: response.accessToken,
          decodedTokenPayload: decodedToken,
          embeddedCnfJkt: decodedToken?.cnf?.jkt,
        },
        status: 'success',
      });

      this.activeToken.set(response.accessToken);
      this.activeUsername.set(response.username);

      const { jwk } = await this.ensureKeyPair();
      const jkt = await computeJkt(jwk);

      return {
        success: response.success,
        message: response.message,
        username: response.username,
        accessToken: response.accessToken,
        dpopThumbprint: jkt,
      };
    } catch (err: any) {
      this.logger.addLog({
        actor: 'Server',
        step: 'Error /api/dpop/login',
        description: `Login failed: ${err?.error?.error || err.message}`,
        details: err?.error || { message: err.message },
        status: 'error',
      });
      throw err;
    }
  }

  async testProtectedGet(): Promise<DPoPProtectedGetResponse> {
    const token = this.activeToken();
    if (!token) {
      throw new Error('Please login first using DPoP to obtain a bound access token.');
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
      step: '2. GET /api/dpop/protected/data with Headers',
      description: 'Client sends Authorization and DPoP headers.',
      headers: {
        'Authorization': `DPoP ${token}`,
        'DPoP': dpopProof,
      },
      status: 'info',
    });

    try {
      const response = await firstValueFrom(
        this.http.get<DPoPProtectedGetResponse>(this.PROTECTED_URL, {
          headers: {
            Authorization: `DPoP ${token}`,
            DPoP: dpopProof,
          },
        })
      );

      this.logger.addLog({
        actor: 'Server',
        step: '3. Protected GET Response',
        description: 'Server verified Proof-of-Possession signature and thumbprint match. Access granted!',
        status: 'success',
      });

      return response;
    } catch (err: any) {
      this.logger.addLog({
        actor: 'Server',
        step: 'Protected GET Failed',
        description: `Server rejected DPoP request: ${err?.error?.error || err.message}`,
        details: err?.error || { message: err.message },
        status: 'error',
      });
      throw err;
    }
  }

  async testProtectedPost(payload: any): Promise<DPoPProtectedPostResponse> {
    const token = this.activeToken();
    if (!token) {
      throw new Error('Please login first using DPoP to obtain a bound access token.');
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
      step: '2. POST /api/dpop/protected/data with Headers',
      description: 'Client sends Authorization and DPoP proof headers.',
      headers: {
        'Authorization': `DPoP ${token}`,
        'DPoP': dpopProof,
      },
      status: 'info',
    });

    try {
      const response = await firstValueFrom(
        this.http.post<DPoPProtectedPostResponse>(this.PROTECTED_URL, payload, {
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
        description: `Server rejected DPoP POST request: ${err?.error?.error || err.message}`,
        details: err?.error || { message: err.message },
        status: 'error',
      });
      throw err;
    }
  }
}

