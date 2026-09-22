import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

export interface JwtAccessTokenPayload {
  sub: string;
  token_type: 'Bearer' | 'DPoP';
  auth_method?: string;
  cnf?: {
    jkt: string;
  };
  iat: number;
  exp: number;
}

export interface LoginStatePayload {
  username: string;
  serverLoginState: string;
  iat: number;
  exp: number;
}

class JwtService {
  private secret!: string;
  private readonly SECRET_FILE = path.join(process.cwd(), '.jwt-secret');

  constructor() {
    this.initSecret();
  }

  private initSecret() {
    if (process.env.JWT_SECRET) {
      this.secret = process.env.JWT_SECRET;
    } else if (fs.existsSync(this.SECRET_FILE)) {
      this.secret = fs.readFileSync(this.SECRET_FILE, 'utf-8').trim();
    } else {
      this.secret = crypto.randomBytes(32).toString('hex');
      fs.writeFileSync(this.SECRET_FILE, this.secret, 'utf-8');
    }
  }

  private base64UrlEncode(data: string | Buffer): string {
    const buf = typeof data === 'string' ? Buffer.from(data, 'utf-8') : data;
    return buf.toString('base64url');
  }

  private base64UrlDecode(str: string): string {
    return Buffer.from(str, 'base64url').toString('utf-8');
  }

  signJwt(payload: Record<string, any>, expiresInSec = 3600): string {
    const header = { alg: 'HS256', typ: 'JWT' };
    const now = Math.floor(Date.now() / 1000);
    const fullPayload = {
      ...payload,
      iat: payload.iat ?? now,
      exp: payload.exp ?? now + expiresInSec,
    };

    const headerB64 = this.base64UrlEncode(JSON.stringify(header));
    const payloadB64 = this.base64UrlEncode(JSON.stringify(fullPayload));
    const signingInput = `${headerB64}.${payloadB64}`;
    const signature = crypto
      .createHmac('sha256', this.secret)
      .update(signingInput)
      .digest('base64url');

    return `${signingInput}.${signature}`;
  }

  verifyJwt<T = any>(token: string): T {
    if (!token || typeof token !== 'string') {
      const error: any = new Error('Token is missing or invalid');
      error.statusCode = 401;
      throw error;
    }

    const parts = token.split('.');
    if (parts.length !== 3) {
      const error: any = new Error('Malformed JWT');
      error.statusCode = 401;
      throw error;
    }

    const [headerB64, payloadB64, sigB64] = parts;
    const signingInput = `${headerB64}.${payloadB64}`;
    const expectedSig = crypto
      .createHmac('sha256', this.secret)
      .update(signingInput)
      .digest('base64url');

    if (sigB64 !== expectedSig) {
      const error: any = new Error('Invalid JWT signature');
      error.statusCode = 401;
      throw error;
    }

    let payload: T & { exp?: number; nbf?: number };
    try {
      payload = JSON.parse(this.base64UrlDecode(payloadB64));
    } catch {
      const error: any = new Error('Invalid JWT payload encoding');
      error.statusCode = 401;
      throw error;
    }

    const now = Math.floor(Date.now() / 1000);
    if (payload.exp && now > payload.exp) {
      const error: any = new Error('JWT token has expired');
      error.statusCode = 401;
      throw error;
    }

    return payload;
  }

  signLoginState(data: { username: string; serverLoginState: string }, expiresInSec = 300): string {
    return this.signJwt(data, expiresInSec);
  }

  verifyLoginState(stateToken: string): { username: string; serverLoginState: string } {
    try {
      const payload = this.verifyJwt<LoginStatePayload>(stateToken);
      if (!payload.username || !payload.serverLoginState) {
        const error: any = new Error('Invalid login state token payload');
        error.statusCode = 400;
        throw error;
      }
      return {
        username: payload.username,
        serverLoginState: payload.serverLoginState,
      };
    } catch (err: any) {
      const error: any = new Error(err.message || 'Invalid or expired login state');
      error.statusCode = 400;
      throw error;
    }
  }

  mintAccessToken(
    username: string,
    options?: { jkt?: string; authMethod?: string; expiresInSec?: number }
  ): string {
    const payload: Partial<JwtAccessTokenPayload> = {
      sub: username,
      token_type: options?.jkt ? 'DPoP' : 'Bearer',
      ...(options?.authMethod ? { auth_method: options.authMethod } : {}),
      ...(options?.jkt ? { cnf: { jkt: options.jkt } } : {}),
    };

    return this.signJwt(payload, options?.expiresInSec ?? 3600);
  }
}

export const jwtService = new JwtService();

