import { Injectable, signal } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import * as opaque from '@serenity-kit/opaque';
import { firstValueFrom } from 'rxjs';
import { environment } from '../../../environments/environment';
import { AuthStrategy } from '../auth-strategy.interface';
import { AuthResult, ProtectedResponse } from '../auth.types';
import { ProtocolLoggerService } from '../logger.service';

@Injectable({
  providedIn: 'root',
})
export class OpaqueStrategy implements AuthStrategy {
  readonly id = 'opaque' as const;
  readonly name = 'OPAQUE';
  readonly description =
    'Asymmetric Password-Authenticated Key Exchange. The server never sees the password and stores no password hash.';

  private readonly API_BASE = environment.apiUrl.replace(/\/auth$/, '');
  private readonly AUTH_URL = `${this.API_BASE}/auth`;
  private readonly PROTECTED_URL = `${this.API_BASE}/protected/opaque/data`;

  readonly activeSessionKey = signal<string | null>(null);
  readonly activeUsername = signal<string | null>(null);

  constructor(
    private http: HttpClient,
    private logger: ProtocolLoggerService
  ) {}

  reset() {
    this.activeSessionKey.set(null);
    this.activeUsername.set(null);
  }

  async register(username: string, password: string): Promise<AuthResult> {
    await opaque.ready;

    this.logger.addLog({
      actor: 'Client',
      step: '1. opaque.client.startRegistration',
      description:
        'Client starts registration: locally generates a blinded registrationRequest. Password never leaves browser!',
      status: 'info',
    });

    const { clientRegistrationState, registrationRequest } = opaque.client.startRegistration({
      password,
    });

    this.logger.addLog({
      actor: 'Client',
      step: '1. opaque.client.startRegistration (Output)',
      description: 'Blinded registrationRequest generated alongside local clientRegistrationState.',
      details: { registrationRequest, clientRegistrationState },
      status: 'info',
    });

    this.logger.addLog({
      actor: 'Network',
      step: '2. POST /api/auth/register/start',
      description: 'Client transmits username and blinded registrationRequest to server.',
      details: { url: `${this.AUTH_URL}/register/start`, body: { username, registrationRequest } },
      status: 'info',
    });

    let startResponse: { registrationResponse: string };
    try {
      startResponse = await firstValueFrom(
        this.http.post<{ registrationResponse: string }>(`${this.AUTH_URL}/register/start`, {
          username,
          registrationRequest,
        })
      );
    } catch (err: any) {
      this.logger.addLog({
        actor: 'Server',
        step: 'Error /api/auth/register/start',
        description: `Server returned error: ${err?.error?.error || err.message}`,
        details: err?.error || { message: err.message },
        status: 'error',
      });
      throw err;
    }

    this.logger.addLog({
      actor: 'Server',
      step: '3. Response from /api/auth/register/start',
      description: 'Server computed registrationResponse using serverSetup private key.',
      details: startResponse,
      status: 'info',
    });

    this.logger.addLog({
      actor: 'Client',
      step: '4. opaque.client.finishRegistration',
      description:
        'Client computes encrypted registrationRecord envelope, client-only exportKey, and serverStaticPublicKey.',
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
      description: 'Encrypted registrationRecord created (safe for server to store).',
      details: { registrationRecord, exportKey, serverStaticPublicKey },
      status: 'info',
    });

    this.logger.addLog({
      actor: 'Network',
      step: '5. POST /api/auth/register/finish',
      description: 'Client sends registrationRecord to server for persistent storage.',
      details: { url: `${this.AUTH_URL}/register/finish`, body: { username, registrationRecord } },
      status: 'info',
    });

    let finishResponse: { success: boolean; message: string };
    try {
      finishResponse = await firstValueFrom(
        this.http.post<{ success: boolean; message: string }>(`${this.AUTH_URL}/register/finish`, {
          username,
          registrationRecord,
        })
      );
    } catch (err: any) {
      this.logger.addLog({
        actor: 'Server',
        step: 'Error /api/auth/register/finish',
        description: `Server returned error: ${err?.error?.error || err.message}`,
        details: err?.error || { message: err.message },
        status: 'error',
      });
      throw err;
    }

    this.logger.addLog({
      actor: 'Server',
      step: '6. Registration Finished',
      description: 'Server stored registrationRecord in users.json. Password was never exposed!',
      details: finishResponse,
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

    this.logger.addLog({
      actor: 'Client',
      step: '1. opaque.client.startLogin',
      description: 'Client generates blinded startLoginRequest and saves clientLoginState.',
      status: 'info',
    });

    const { clientLoginState, startLoginRequest } = opaque.client.startLogin({
      password,
    });

    this.logger.addLog({
      actor: 'Client',
      step: '1. opaque.client.startLogin (Output)',
      description: 'Blinded startLoginRequest ready for transmission.',
      details: { startLoginRequest, clientLoginState },
      status: 'info',
    });

    this.logger.addLog({
      actor: 'Network',
      step: '2. POST /api/auth/login/start',
      description: 'Client sends username and startLoginRequest to server.',
      details: { url: `${this.AUTH_URL}/login/start`, body: { username, startLoginRequest } },
      status: 'info',
    });

    let startResponse: { loginSessionId: string; loginResponse: string };
    try {
      startResponse = await firstValueFrom(
        this.http.post<{ loginSessionId: string; loginResponse: string }>(
          `${this.AUTH_URL}/login/start`,
          { username, startLoginRequest }
        )
      );
    } catch (err: any) {
      this.logger.addLog({
        actor: 'Server',
        step: 'Error /api/auth/login/start',
        description: `Server error: ${err?.error?.error || err.message}`,
        details: err?.error || { message: err.message },
        status: 'error',
      });
      throw err;
    }

    this.logger.addLog({
      actor: 'Server',
      step: '3. Response from /api/auth/login/start',
      description: 'Server computed loginResponse and stored serverLoginState in temporary session.',
      details: startResponse,
      status: 'info',
    });

    this.logger.addLog({
      actor: 'Client',
      step: '4. opaque.client.finishLogin',
      description:
        'Client attempts to unlock envelope using password. Computes sessionKey and finishLoginRequest proof.',
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
      step: '4. opaque.client.finishLogin (Output)',
      description: 'Envelope unlocked! Derived sessionKey, exportKey, and finishLoginRequest proof.',
      details: { finishLoginRequest, clientSessionKey, exportKey, serverStaticPublicKey },
      status: 'info',
    });

    this.logger.addLog({
      actor: 'Network',
      step: '5. POST /api/auth/login/finish',
      description: 'Client sends finishLoginRequest proof and loginSessionId to server.',
      details: {
        url: `${this.AUTH_URL}/login/finish`,
        body: { loginSessionId: startResponse.loginSessionId, finishLoginRequest },
      },
      status: 'info',
    });

    let finishResponse: { success: boolean; message: string; sessionKey: string; username: string };
    try {
      finishResponse = await firstValueFrom(
        this.http.post<{ success: boolean; message: string; sessionKey: string; username: string }>(
          `${this.AUTH_URL}/login/finish`,
          { loginSessionId: startResponse.loginSessionId, finishLoginRequest }
        )
      );
    } catch (err: any) {
      this.logger.addLog({
        actor: 'Server',
        step: 'Error /api/auth/login/finish',
        description: `Server rejected proof: ${err?.error?.error || err.message}`,
        details: err?.error || { message: err.message },
        status: 'error',
      });
      throw err;
    }

    const keysMatch = finishResponse.sessionKey === clientSessionKey;
    this.logger.addLog({
      actor: 'Server',
      step: '6. Login Verified by Server',
      description: `Server authenticated proof. Session keys ${keysMatch ? 'MATCHED PERFECTLY' : 'MISMATCHED'}!`,
      details: {
        serverSessionKey: finishResponse.sessionKey,
        clientSessionKey,
        keysMatch,
      },
      status: keysMatch ? 'success' : 'error',
    });

    this.activeSessionKey.set(clientSessionKey);
    this.activeUsername.set(finishResponse.username);

    return {
      success: finishResponse.success,
      message: finishResponse.message,
      username: finishResponse.username,
      sessionKey: clientSessionKey,
      exportKey,
      serverStaticPublicKey,
    };
  }

  async testProtectedGet(): Promise<ProtectedResponse> {
    const sessionKey = this.activeSessionKey();
    if (!sessionKey) {
      throw new Error('Please login first using OPAQUE to obtain an active sessionKey.');
    }

    this.logger.addLog({
      actor: 'Client',
      step: 'Protected GET (OPAQUE)',
      description: 'Client initiates protected GET request with Authorization: Bearer <sessionKey>',
      details: { url: this.PROTECTED_URL, sessionKey },
      status: 'info',
    });

    try {
      const response = await firstValueFrom(
        this.http.get<ProtectedResponse>(this.PROTECTED_URL, {
          headers: { Authorization: `Bearer ${sessionKey}` },
        })
      );

      this.logger.addLog({
        actor: 'Server',
        step: 'Protected GET Response (OPAQUE)',
        description: 'Server validated sessionKey and returned confidential resource.',
        details: response,
        status: 'success',
      });

      return response;
    } catch (err: any) {
      this.logger.addLog({
        actor: 'Server',
        step: 'Protected GET Failed (OPAQUE)',
        description: `Server rejected request: ${err?.error?.error || err.message}`,
        details: err?.error || { message: err.message },
        status: 'error',
      });
      throw err;
    }
  }

  async testProtectedPost(payload: any): Promise<ProtectedResponse> {
    const sessionKey = this.activeSessionKey();
    if (!sessionKey) {
      throw new Error('Please login first using OPAQUE to obtain an active sessionKey.');
    }

    this.logger.addLog({
      actor: 'Client',
      step: 'Protected POST (OPAQUE)',
      description: 'Client sends data to protected endpoint with Authorization: Bearer <sessionKey>',
      details: { url: this.PROTECTED_URL, sessionKey, payload },
      status: 'info',
    });

    try {
      const response = await firstValueFrom(
        this.http.post<ProtectedResponse>(this.PROTECTED_URL, payload, {
          headers: { Authorization: `Bearer ${sessionKey}` },
        })
      );

      this.logger.addLog({
        actor: 'Server',
        step: 'Protected POST Response (OPAQUE)',
        description: 'Server validated sessionKey and processed payload successfully.',
        details: response,
        status: 'success',
      });

      return response;
    } catch (err: any) {
      this.logger.addLog({
        actor: 'Server',
        step: 'Protected POST Failed (OPAQUE)',
        description: `Server rejected request: ${err?.error?.error || err.message}`,
        details: err?.error || { message: err.message },
        status: 'error',
      });
      throw err;
    }
  }
}
