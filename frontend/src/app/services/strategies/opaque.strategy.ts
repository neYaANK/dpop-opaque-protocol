import { Injectable, signal } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import * as opaque from '@serenity-kit/opaque';
import { firstValueFrom } from 'rxjs';
import { environment } from '../../../environments/environment';
import { AuthStrategy } from '../auth-strategy.interface';
import {
  AuthResult,
  ProtectedResponse,
  OpaqueRegisterStartRequest,
  OpaqueRegisterStartResponse,
  OpaqueRegisterFinishRequest,
  OpaqueRegisterFinishResponse,
  OpaqueLoginStartRequest,
  OpaqueLoginStartResponse,
  OpaqueLoginFinishRequest,
  OpaqueLoginFinishResponse,
  OpaqueProtectedGetResponse,
  OpaqueProtectedPostResponse,
} from '../auth.types';
import { ProtocolLoggerService } from '../logger.service';

@Injectable({
  providedIn: 'root',
})
export class OpaqueStrategy implements AuthStrategy {
  readonly id = 'opaque' as const;
  readonly name = 'OPAQUE';
  readonly description =
    'Asymmetric Password-Authenticated Key Exchange. The server never sees the password and stores no password hash.';

  private readonly BASE_URL = `${environment.apiUrl}/opaque`;
  private readonly REGISTER_START_URL = `${this.BASE_URL}/register/start`;
  private readonly REGISTER_FINISH_URL = `${this.BASE_URL}/register/finish`;
  private readonly LOGIN_START_URL = `${this.BASE_URL}/login/start`;
  private readonly LOGIN_FINISH_URL = `${this.BASE_URL}/login/finish`;
  private readonly PROTECTED_URL = `${this.BASE_URL}/protected/data`;

  readonly activeToken = signal<string | null>(null);
  readonly activeSessionKey = signal<string | null>(null);
  readonly activeUsername = signal<string | null>(null);

  constructor(
    private http: HttpClient,
    private logger: ProtocolLoggerService
  ) {}

  reset() {
    this.activeToken.set(null);
    this.activeSessionKey.set(null);
    this.activeUsername.set(null);
  }

  async register(username: string, password: string): Promise<AuthResult> {
    await opaque.ready;

    const { clientRegistrationState, registrationRequest } = opaque.client.startRegistration({
      password,
    });

    this.logger.addLog({
      actor: 'Client',
      step: '1. opaque.client.startRegistration',
      description: 'Client starts registration: locally generates a blinded registrationRequest. Password never leaves browser',
      crypto: { registrationRequest, clientRegistrationState },
      status: 'info',
    });

    const startPayload: OpaqueRegisterStartRequest = { username, registrationRequest };
    this.logger.addLog({
      actor: 'Network',
      step: '2. POST /api/opaque/register/start',
      description: 'Client transmits username and blinded registrationRequest to server.',
      body: startPayload,
      status: 'info',
    });

    let startResponse: OpaqueRegisterStartResponse;
    try {
      startResponse = await firstValueFrom(
        this.http.post<OpaqueRegisterStartResponse>(this.REGISTER_START_URL, startPayload)
      );
    } catch (err: any) {
      this.logger.addLog({
        actor: 'Server',
        step: 'Error /api/opaque/register/start',
        description: `Server returned error: ${err?.error?.error || err.message}`,
        details: err?.error || { message: err.message },
        status: 'error',
      });
      throw err;
    }

    this.logger.addLog({
      actor: 'Server',
      step: '3. Response from /api/opaque/register/start',
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
      description: 'Client computes encrypted registrationRecord envelope',
      crypto: { registrationRecord, exportKey, serverStaticPublicKey },
      status: 'info',
    });

    const finishPayload: OpaqueRegisterFinishRequest = { username, registrationRecord };
    this.logger.addLog({
      actor: 'Network',
      step: '5. POST /api/opaque/register/finish',
      description: 'Client sends registrationRecord to server for persistent storage.',
      body: finishPayload,
      status: 'info',
    });

    let finishResponse: OpaqueRegisterFinishResponse;
    try {
      finishResponse = await firstValueFrom(
        this.http.post<OpaqueRegisterFinishResponse>(this.REGISTER_FINISH_URL, finishPayload)
      );
    } catch (err: any) {
      this.logger.addLog({
        actor: 'Server',
        step: 'Error /api/opaque/register/finish',
        description: `Server returned error: ${err?.error?.error || err.message}`,
        details: err?.error || { message: err.message },
        status: 'error',
      });
      throw err;
    }

    this.logger.addLog({
      actor: 'Server',
      step: '6. Response from /api/opaque/register/finish',
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
      description: 'Client generates blinded startLoginRequest and saves clientLoginState',
      crypto: { startLoginRequest, clientLoginState },
      status: 'info',
    });

    const startPayload: OpaqueLoginStartRequest = { username, startLoginRequest };
    this.logger.addLog({
      actor: 'Network',
      step: '2. POST /api/opaque/login/start',
      description: 'Client sends username and startLoginRequest to server.',
      body: startPayload,
      status: 'info',
    });

    let startResponse: OpaqueLoginStartResponse;
    try {
      startResponse = await firstValueFrom(
        this.http.post<OpaqueLoginStartResponse>(
          this.LOGIN_START_URL,
          startPayload
        )
      );
    } catch (err: any) {
      this.logger.addLog({
        actor: 'Server',
        step: 'Error /api/opaque/login/start',
        description: `Server error: ${err?.error?.error || err.message}`,
        details: err?.error || { message: err.message },
        status: 'error',
      });
      throw err;
    }

    this.logger.addLog({
      actor: 'Server',
      step: '3. Response from /api/opaque/login/start',
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

    const finishPayload: OpaqueLoginFinishRequest = {
      loginSessionId: startResponse.loginSessionId,
      finishLoginRequest,
    };
    this.logger.addLog({
      actor: 'Network',
      step: '5. POST /api/opaque/login/finish',
      description: 'Client sends finishLoginRequest proof and loginSessionId to server.',
      body: finishPayload,
      status: 'info',
    });

    let finishResponse: OpaqueLoginFinishResponse;
    try {
      finishResponse = await firstValueFrom(
        this.http.post<OpaqueLoginFinishResponse>(
          this.LOGIN_FINISH_URL,
          finishPayload
        )
      );
    } catch (err: any) {
      this.logger.addLog({
        actor: 'Server',
        step: 'Error /api/opaque/login/finish',
        description: `Server rejected proof: ${err?.error?.error || err.message}`,
        details: err?.error || { message: err.message },
        status: 'error',
      });
      throw err;
    }

    this.logger.addLog({
      actor: 'Server',
      step: '6. Response from /api/opaque/login/finish',
      description: 'Server authenticated proof and issued JWT access token!',
      body: finishResponse,
      crypto: {
        clientSessionKey,
        issuedAccessToken: finishResponse.accessToken,
      },
      status: 'success',
    });

    this.activeToken.set(finishResponse.accessToken);
    this.activeSessionKey.set(clientSessionKey);
    this.activeUsername.set(finishResponse.username);

    return {
      success: finishResponse.success,
      message: finishResponse.message,
      username: finishResponse.username,
      accessToken: finishResponse.accessToken,
      sessionKey: clientSessionKey,
      exportKey,
      serverStaticPublicKey,
    };
  }

  async testProtectedGet(): Promise<OpaqueProtectedGetResponse> {
    const token = this.activeToken();
    if (!token) {
      throw new Error('Please login first using OPAQUE to obtain an active access token.');
    }

    this.logger.addLog({
      actor: 'Network',
      step: '1. GET /api/opaque/protected/data',
      description: 'Client initiates protected GET request with Authorization: Bearer <accessToken>',
      headers: {
        'Authorization': `Bearer ${token}`,
      },
      status: 'info',
    });

    try {
      const response = await firstValueFrom(
        this.http.get<OpaqueProtectedGetResponse>(this.PROTECTED_URL, {
          headers: { Authorization: `Bearer ${token}` },
        })
      );

      this.logger.addLog({
        actor: 'Server',
        step: '2. Response from /api/opaque/protected/data',
        description: 'Server validated access token and returned confidential resource.',
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

  async testProtectedPost(payload: any): Promise<OpaqueProtectedPostResponse> {
    const token = this.activeToken();
    if (!token) {
      throw new Error('Please login first using OPAQUE to obtain an active access token.');
    }

    this.logger.addLog({
      actor: 'Network',
      step: '1. POST /api/opaque/protected/data',
      description: 'Client sends data to protected endpoint with Authorization: Bearer <accessToken>',
      headers: {
        'Authorization': `Bearer ${token}`,
      },
      status: 'info',
    });

    try {
      const response = await firstValueFrom(
        this.http.post<OpaqueProtectedPostResponse>(this.PROTECTED_URL, payload, {
          headers: { Authorization: `Bearer ${token}` },
        })
      );

      this.logger.addLog({
        actor: 'Server',
        step: '2. Response from /api/opaque/protected/data',
        description: 'Server validated access token and processed payload successfully.',
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
