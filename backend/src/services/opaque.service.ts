import fs from 'node:fs';
import path from 'node:path';
import * as opaque from '@serenity-kit/opaque';
import { db } from '../db.ts';
import { jwtService } from './jwt.service.ts';
import type {
  OpaqueRegisterStartRequest,
  OpaqueRegisterStartResponse,
  OpaqueRegisterFinishRequest,
  OpaqueRegisterFinishResponse,
  OpaqueLoginStartRequest,
  OpaqueLoginStartResponse,
  OpaqueLoginFinishRequest,
  OpaqueLoginFinishResponse,
} from '../types/index.ts';

class OpaqueService {
  private serverSetup!: string;
  private readonly SETUP_FILE = path.join(process.cwd(), '.server-setup');

  async init() {
    await opaque.ready;

    if (process.env.OPAQUE_SERVER_SETUP) {
      this.serverSetup = process.env.OPAQUE_SERVER_SETUP;
    } else if (fs.existsSync(this.SETUP_FILE)) {
      this.serverSetup = fs.readFileSync(this.SETUP_FILE, 'utf-8').trim();
    } else {
      this.serverSetup = opaque.server.createSetup();
      fs.writeFileSync(this.SETUP_FILE, this.serverSetup, 'utf-8');
    }
  }

  registerStart(data: OpaqueRegisterStartRequest): OpaqueRegisterStartResponse {
    const { username, registrationRequest } = data;

    if (db.has(username) && db.get(username)?.registrationRecord) {
      const error: any = new Error('User already exists');
      error.statusCode = 409;
      throw error;
    }

    const { registrationResponse } = opaque.server.createRegistrationResponse({
      serverSetup: this.serverSetup,
      userIdentifier: username,
      registrationRequest,
    });

    return { registrationResponse };
  }

  registerFinish(data: OpaqueRegisterFinishRequest): OpaqueRegisterFinishResponse {
    const { username, registrationRecord } = data;

    if (db.has(username) && db.get(username)?.registrationRecord) {
      const error: any = new Error('User already exists');
      error.statusCode = 409;
      throw error;
    }

    const existing = db.get(username) || {};
    db.set(username, { ...existing, registrationRecord });

    return { success: true, message: 'User registered successfully with OPAQUE' };
  }

  loginStart(data: OpaqueLoginStartRequest): OpaqueLoginStartResponse {
    const { username, startLoginRequest } = data;

    const user = db.get(username);
    if (!user || !user.registrationRecord) {
      const error: any = new Error('User not found or not registered with OPAQUE');
      error.statusCode = 404;
      throw error;
    }

    const { loginResponse, serverLoginState } = opaque.server.startLogin({
      userIdentifier: username,
      registrationRecord: user.registrationRecord,
      serverSetup: this.serverSetup,
      startLoginRequest,
    });

    const loginSessionId = jwtService.signLoginState({ username, serverLoginState });

    return { loginSessionId, loginResponse };
  }

  finishOpaqueLoginHandshake(loginSessionId: string, finishLoginRequest: string): { username: string; sessionKey: string } {
    const session = jwtService.verifyLoginState(loginSessionId);

    const { sessionKey } = opaque.server.finishLogin({
      finishLoginRequest,
      serverLoginState: session.serverLoginState,
    });

    return {
      username: session.username,
      sessionKey,
    };
  }

  loginFinish(data: OpaqueLoginFinishRequest): OpaqueLoginFinishResponse {
    const { loginSessionId, finishLoginRequest } = data;
    const { username } = this.finishOpaqueLoginHandshake(loginSessionId, finishLoginRequest);

    const accessToken = jwtService.mintAccessToken(username, { authMethod: 'opaque' });

    return {
      success: true,
      message: 'Login successful',
      username,
      accessToken,
    };
  }

  validateToken(token: string): string {
    const payload = jwtService.verifyJwt(token);
    if (!payload.sub) {
      const error: any = new Error('Unauthorized: Invalid token subject');
      error.statusCode = 401;
      throw error;
    }
    return payload.sub;
  }
}

export const opaqueService = new OpaqueService();
