import crypto from 'node:crypto';
import { db } from '../db.ts';
import { jwtService } from './jwt.service.ts';
import type {
  DPoPRegisterRequest,
  DPoPRegisterResponse,
  DPoPLoginRequest,
  DPoPLoginResponse,
} from '../types/index.ts';

class DPoPService {
  computeJwkThumbprint(jwk: { crv: string; kty: string; x: string; y: string }): string {
    const canonical = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y });
    return crypto.createHash('sha256').update(canonical).digest('base64url');
  }

  verifyDPoPProof(
    dpopHeader: string | undefined,
    expectedMethod: string,
    expectedUrlPath: string,
    accessToken?: string
  ): { valid: boolean; jkt?: string; error?: string } {
    if (!dpopHeader) {
      return { valid: false, error: 'Missing DPoP header' };
    }

    try {
      const parts = dpopHeader.split('.');
      if (parts.length !== 3) {
        return { valid: false, error: 'Invalid DPoP JWT format' };
      }

      const [headerB64, payloadB64, sigB64] = parts;
      const header = JSON.parse(Buffer.from(headerB64, 'base64url').toString('utf-8'));
      const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf-8'));

      if (header.typ !== 'dpop+jwt' || header.alg !== 'ES256' || !header.jwk) {
        return { valid: false, error: 'Invalid DPoP header (expected typ: dpop+jwt, alg: ES256, jwk)' };
      }

      const jwk = header.jwk;
      if (jwk.kty !== 'EC' || jwk.crv !== 'P-256' || !jwk.x || !jwk.y) {
        return { valid: false, error: 'Invalid JWK in DPoP header' };
      }

      const now = Math.floor(Date.now() / 1000);
      if (!payload.iat || Math.abs(now - payload.iat) > 300) {
        return { valid: false, error: 'DPoP proof expired or timestamp skewed' };
      }

      if (payload.htm?.toUpperCase() !== expectedMethod.toUpperCase()) {
        return { valid: false, error: `DPoP htm mismatch (expected ${expectedMethod}, got ${payload.htm})` };
      }

      if (payload.htu && !payload.htu.includes(expectedUrlPath)) {
        return { valid: false, error: `DPoP htu mismatch (expected ${expectedUrlPath} in ${payload.htu})` };
      }

      if (accessToken && payload.ath) {
        const expectedAth = crypto.createHash('sha256').update(accessToken).digest('base64url');
        if (payload.ath !== expectedAth) {
          return { valid: false, error: 'DPoP ath mismatch (access token hash invalid)' };
        }
      }

      const signingInput = Buffer.from(`${headerB64}.${payloadB64}`);
      const publicKey = crypto.createPublicKey({ key: jwk, format: 'jwk' });
      const signature = Buffer.from(sigB64, 'base64url');

      const isVerified = crypto.verify(
        'SHA256',
        signingInput,
        { key: publicKey, dsaEncoding: 'ieee-p1363' },
        signature
      );

      if (!isVerified) {
        return { valid: false, error: 'DPoP cryptographic signature verification failed' };
      }

      const jkt = this.computeJwkThumbprint(jwk);
      return { valid: true, jkt };
    } catch (err: any) {
      return { valid: false, error: `DPoP parsing error: ${err.message}` };
    }
  }

  register(data: DPoPRegisterRequest): DPoPRegisterResponse {
    const { username, password } = data;

    if (db.has(username) && db.get(username)?.passwordHash) {
      const error: any = new Error('User already exists');
      error.statusCode = 409;
      throw error;
    }

    const passwordHash = crypto.createHash('sha256').update(password).digest('hex');
    const existing = db.get(username) || {};
    db.set(username, { ...existing, passwordHash });

    return { success: true, message: 'User registered successfully with DPoP credentials' };
  }

  login(data: DPoPLoginRequest, dpopHeader?: string): DPoPLoginResponse {
    const { username, password } = data;

    const user = db.get(username);
    if (!user || !user.passwordHash) {
      const error: any = new Error('User not found or not registered with DPoP');
      error.statusCode = 404;
      throw error;
    }

    const hash = crypto.createHash('sha256').update(password).digest('hex');
    if (user.passwordHash !== hash) {
      const error: any = new Error('Invalid password');
      error.statusCode = 401;
      throw error;
    }

    const dpopVerification = this.verifyDPoPProof(dpopHeader, 'POST', '/api/dpop/login');
    if (!dpopVerification.valid || !dpopVerification.jkt) {
      const error: any = new Error(`DPoP verification failed: ${dpopVerification.error}`);
      error.statusCode = 400;
      throw error;
    }

    const accessToken = jwtService.mintAccessToken(username, { jkt: dpopVerification.jkt });

    return {
      success: true,
      message: 'DPoP login successful. Token bound to public key thumbprint.',
      username,
      accessToken,
    };
  }

  validateAuth(
    authHeader: string | undefined,
    dpopHeader: string | undefined,
    method: string,
    urlPath: string
  ): { user: string; jkt: string } {
    if (!authHeader || !authHeader.startsWith('DPoP ')) {
      const error: any = new Error('Unauthorized: Missing or malformed Authorization: DPoP <token> header');
      error.statusCode = 401;
      throw error;
    }

    const token = authHeader.slice(5).trim();
    let tokenPayload: any;
    try {
      tokenPayload = jwtService.verifyJwt(token);
    } catch (err: any) {
      const error: any = new Error(`Unauthorized: Invalid or expired DPoP access token (${err.message})`);
      error.statusCode = 401;
      throw error;
    }

    if (!tokenPayload.sub || !tokenPayload.cnf?.jkt) {
      const error: any = new Error('Unauthorized: Access token missing subject or DPoP key binding confirmation');
      error.statusCode = 401;
      throw error;
    }

    const dpopVerification = this.verifyDPoPProof(dpopHeader, method, urlPath, token);
    if (!dpopVerification.valid) {
      const error: any = new Error(`DPoP proof invalid: ${dpopVerification.error}`);
      error.statusCode = 401;
      throw error;
    }

    if (dpopVerification.jkt !== tokenPayload.cnf.jkt) {
      const error: any = new Error(
        'DPoP key binding mismatch: Proof key does not match token thumbprint (Proof-of-Possession failed)'
      );
      error.statusCode = 401;
      throw error;
    }

    return { user: tokenPayload.sub, jkt: tokenPayload.cnf.jkt };
  }
}

export const dpopService = new DPoPService();
