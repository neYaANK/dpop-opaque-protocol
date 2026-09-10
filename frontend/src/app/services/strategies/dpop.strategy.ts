import { Injectable, signal } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { firstValueFrom } from 'rxjs';
import { environment } from '../../../environments/environment';
import { AuthStrategy } from '../auth-strategy.interface';
import { AuthResult, ProtectedResponse } from '../auth.types';
import { ProtocolLoggerService } from '../logger.service';

function base64UrlEncode(buffer: ArrayBuffer | Uint8Array | string): string {
  let str = '';
  if (typeof buffer === 'string') {
    str = btoa(unescape(encodeURIComponent(buffer)));
  } else {
    const bytes = new Uint8Array(buffer);
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

  private readonly API_BASE = environment.apiUrl.replace(/\/auth$/, '');
  private readonly DPOP_AUTH_URL = `${this.API_BASE}/dpop`;
  private readonly PROTECTED_URL = `${this.API_BASE}/protected/dpop/data`;

  private keyPair: CryptoKeyPair | null = null;
  private jwk: any | null = null;
  private jkt: string | null = null;

  readonly activeToken = signal<string | null>(null);
  readonly activeUsername = signal<string | null>(null);
  readonly activeThumbprint = signal<string | null>(null);

  constructor(
    private http: HttpClient,
    private logger: ProtocolLoggerService
  ) {}

  reset() {
    this.keyPair = null;
    this.jwk = null;
    this.jkt = null;
    this.activeToken.set(null);
    this.activeUsername.set(null);
    this.activeThumbprint.set(null);
  }

  private async ensureKeyPair(): Promise<{ keyPair: CryptoKeyPair; jwk: any; jkt: string }> {
    if (this.keyPair && this.jwk && this.jkt) {
      return { keyPair: this.keyPair, jwk: this.jwk, jkt: this.jkt };
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
    this.jkt = jkt;
    this.activeThumbprint.set(jkt);

    this.logger.addLog({
      actor: 'Client',
      step: 'WebCrypto: Public JWK & Thumbprint (JKT)',
      description: 'Exported public JWK and calculated canonical SHA-256 thumbprint (jkt).',
      details: { jwk, jkt },
      status: 'info',
    });

    return { keyPair, jwk, jkt };
  }

  private async createDPoPProof(method: string, url: string): Promise<string> {
    const { keyPair, jwk } = await this.ensureKeyPair();

    const header = {
      typ: 'dpop+jwt',
      alg: 'ES256',
      jwk,
    };

    const payload = {
      jti: crypto.randomUUID(),
      htm: method.toUpperCase(),
      htu: url,
      iat: Math.floor(Date.now() / 1000),
    };

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
    this.logger.addLog({
      actor: 'Client',
      step: '1. Register with DPoP Credentials',
      description: 'Client sends registration credentials to DPoP register endpoint.',
      details: { url: `${this.DPOP_AUTH_URL}/register`, username },
      status: 'info',
    });

    try {
      const response = await firstValueFrom(
        this.http.post<{ success: boolean; message: string }>(`${this.DPOP_AUTH_URL}/register`, {
          username,
          password,
        })
      );

      this.logger.addLog({
        actor: 'Server',
        step: '2. DPoP Registration Succeeded',
        description: 'Server registered user credentials for DPoP authentication.',
        details: response,
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
    const loginUrl = `${this.DPOP_AUTH_URL}/login`;
    const dpopProof = await this.createDPoPProof('POST', loginUrl);

    this.logger.addLog({
      actor: 'Client',
      step: '1. Generate DPoP Login Proof',
      description: 'Client signed a DPoP proof JWT with private ECDSA key for login request.',
      details: { dpopProofHeader: dpopProof.split('.')[0], dpopProofPayload: base64UrlDecodeJson(dpopProof.split('.')[1]) },
      status: 'info',
    });

    this.logger.addLog({
      actor: 'Network',
      step: '2. POST /api/dpop/login with DPoP Header',
      description: 'Client sends username, password, and DPoP proof header to server.',
      details: { url: loginUrl, headers: { DPoP: dpopProof } },
      status: 'info',
    });

    try {
      const response = await firstValueFrom(
        this.http.post<{
          success: boolean;
          message: string;
          username: string;
          accessToken: string;
          dpopThumbprint: string;
        }>(
          loginUrl,
          { username, password },
          { headers: { DPoP: dpopProof } }
        )
      );

      this.logger.addLog({
        actor: 'Server',
        step: '3. DPoP Login Verified',
        description: 'Server validated credentials and DPoP signature. Issued access token bound to public key thumbprint!',
        details: response,
        status: 'success',
      });

      this.activeToken.set(response.accessToken);
      this.activeUsername.set(response.username);

      return {
        success: response.success,
        message: response.message,
        username: response.username,
        accessToken: response.accessToken,
        dpopThumbprint: response.dpopThumbprint,
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

  async testProtectedGet(): Promise<ProtectedResponse> {
    const token = this.activeToken();
    if (!token) {
      throw new Error('Please login first using DPoP to obtain a bound access token.');
    }

    const dpopProof = await this.createDPoPProof('GET', this.PROTECTED_URL);

    this.logger.addLog({
      actor: 'Client',
      step: 'Generate DPoP Proof for GET',
      description: 'Client created fresh DPoP proof for protected GET endpoint.',
      details: { url: this.PROTECTED_URL, dpopProof },
      status: 'info',
    });

    try {
      const response = await firstValueFrom(
        this.http.get<ProtectedResponse>(this.PROTECTED_URL, {
          headers: {
            Authorization: `DPoP ${token}`,
            DPoP: dpopProof,
          },
        })
      );

      this.logger.addLog({
        actor: 'Server',
        step: 'Protected GET Response (DPoP)',
        description: 'Server verified Proof-of-Possession against bound key and granted access.',
        details: response,
        status: 'success',
      });

      return response;
    } catch (err: any) {
      this.logger.addLog({
        actor: 'Server',
        step: 'Protected GET Failed (DPoP)',
        description: `Server rejected DPoP request: ${err?.error?.error || err.message}`,
        details: err?.error || { message: err.message },
        status: 'error',
      });
      throw err;
    }
  }

  async testProtectedPost(payload: any): Promise<ProtectedResponse> {
    const token = this.activeToken();
    if (!token) {
      throw new Error('Please login first using DPoP to obtain a bound access token.');
    }

    const dpopProof = await this.createDPoPProof('POST', this.PROTECTED_URL);

    this.logger.addLog({
      actor: 'Client',
      step: 'Generate DPoP Proof for POST',
      description: 'Client created fresh DPoP proof for protected POST endpoint.',
      details: { url: this.PROTECTED_URL, dpopProof, payload },
      status: 'info',
    });

    try {
      const response = await firstValueFrom(
        this.http.post<ProtectedResponse>(this.PROTECTED_URL, payload, {
          headers: {
            Authorization: `DPoP ${token}`,
            DPoP: dpopProof,
          },
        })
      );

      this.logger.addLog({
        actor: 'Server',
        step: 'Protected POST Response (DPoP)',
        description: 'Server verified Proof-of-Possession and processed POST data successfully.',
        details: response,
        status: 'success',
      });

      return response;
    } catch (err: any) {
      this.logger.addLog({
        actor: 'Server',
        step: 'Protected POST Failed (DPoP)',
        description: `Server rejected DPoP POST request: ${err?.error?.error || err.message}`,
        details: err?.error || { message: err.message },
        status: 'error',
      });
      throw err;
    }
  }
}
