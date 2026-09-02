import { Injectable, signal } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import * as opaque from '@serenity-kit/opaque';
import { firstValueFrom } from 'rxjs';
import { environment } from '../../environments/environment';

export interface RegisterResult {
  success: boolean;
  message: string;
  exportKey: string;
  serverStaticPublicKey: string;
}

export interface LoginResult {
  success: boolean;
  message: string;
  username: string;
  sessionKey: string;
  exportKey: string;
  serverStaticPublicKey: string;
}

export interface LogEntry {
  id: number;
  time: string;
  actor: 'Client' | 'Server' | 'Network';
  step: string;
  description: string;
  details?: Record<string, any>;
  status: 'info' | 'success' | 'error';
}

@Injectable({
  providedIn: 'root',
})
export class OpaqueService {
  private readonly API_URL = environment.apiUrl;
  private logCounter = 0;

  readonly logs = signal<LogEntry[]>([]);

  constructor(private http: HttpClient) {}

  addLog(entry: Omit<LogEntry, 'id' | 'time'>) {
    const time = new Date().toLocaleTimeString();
    const newEntry: LogEntry = {
      ...entry,
      id: ++this.logCounter,
      time,
    };
    this.logs.update((prev) => [...prev, newEntry]);
  }

  clearLogs() {
    this.logs.set([]);
  }

  /*
    1. startRegistration (Client)
    2. POST /register/start (Network -> Server)
    3. finishRegistration (Client)
    4. POST /register/finish (Network -> Server)
  */
  async register(username: string, password: string): Promise<RegisterResult> {
    await opaque.ready;

    this.addLog({
      actor: 'Client',
      step: '1. opaque.client.startRegistration',
      description: 'Client starts registration: locally generates a blinded registrationRequest and stores clientRegistrationState based on the password. The password itself is NEVER sent to the server!',
      details: {},
      status: 'info',
    });

    const { clientRegistrationState, registrationRequest } = opaque.client.startRegistration({
      password,
    });

    this.addLog({
      actor: 'Client',
      step: '1. opaque.client.startRegistration (Output)',
      description: 'Blinded registrationRequest generated for transmission along with local clientRegistrationState.',
      details: {
        registrationRequest,
        clientRegistrationState,
      },
      status: 'info',
    });

    this.addLog({
      actor: 'Network',
      step: '2. POST /register/start',
      description: 'Client transmits username and blinded registrationRequest to the server.',
      details: {
        url: `${this.API_URL}/register/start`,
        body: { username, registrationRequest },
      },
      status: 'info',
    });

    let startResponse: { registrationResponse: string };
    try {
      startResponse = await firstValueFrom(
        this.http.post<{ registrationResponse: string }>(`${this.API_URL}/register/start`, {
          username,
          registrationRequest,
        })
      );
    } catch (err: any) {
      this.addLog({
        actor: 'Server',
        step: 'Error /register/start',
        description: `Server returned error: ${err?.error?.error || err.message}`,
        details: err?.error || { message: err.message },
        status: 'error',
      });
      throw err;
    }

    this.addLog({
      actor: 'Server',
      step: '3. Response from /register/start',
      description: 'Server verifies user uniqueness and computes registrationResponse using its serverSetup key.',
      details: {
        registrationResponse: startResponse.registrationResponse,
      },
      status: 'info',
    });

    this.addLog({
      actor: 'Client',
      step: '4. opaque.client.finishRegistration',
      description: 'Client completes registration using registrationResponse, clientRegistrationState, and password. Computes registrationRecord, private exportKey, and serverStaticPublicKey.',
      status: 'info',
    });

    const { registrationRecord, exportKey, serverStaticPublicKey } =
      opaque.client.finishRegistration({
        clientRegistrationState,
        registrationResponse: startResponse.registrationResponse,
        password,
      });

    this.addLog({
      actor: 'Client',
      step: '4. opaque.client.finishRegistration (Output)',
      description: 'Computed registrationRecord (stored on server, contains no password/hash), client-only exportKey, and server public key.',
      details: {
        registrationRecord,
        exportKey,
        serverStaticPublicKey,
      },
      status: 'info',
    });

    this.addLog({
      actor: 'Network',
      step: '5. POST /register/finish',
      description: 'Client sends registrationRecord to the server to store in the database.',
      details: {
        url: `${this.API_URL}/register/finish`,
        body: { username, registrationRecord },
      },
      status: 'info',
    });

    let finishResponse: { success: boolean; message: string };
    try {
      finishResponse = await firstValueFrom(
        this.http.post<{ success: boolean; message: string }>(`${this.API_URL}/register/finish`, {
          username,
          registrationRecord,
        })
      );
    } catch (err: any) {
      this.addLog({
        actor: 'Server',
        step: 'Error /register/finish',
        description: `Server returned error: ${err?.error?.error || err.message}`,
        details: err?.error || { message: err.message },
        status: 'error',
      });
      throw err;
    }

    this.addLog({
      actor: 'Server',
      step: '6. Registration Finished',
      description: 'Server saved registrationRecord to database. Password was never exposed or stored on the server!',
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

  /*
    1. startLogin (Client)
    2. POST /login/start (Network -> Server)
    3. finishLogin (Client)
    4. POST /login/finish (Network -> Server)
  */
  async login(username: string, password: string): Promise<LoginResult> {
    await opaque.ready;

    this.addLog({
      actor: 'Client',
      step: '1. opaque.client.startLogin',
      description: 'Client initiates login: generates blinded startLoginRequest and saves clientLoginState.',
      status: 'info',
    });

    const { clientLoginState, startLoginRequest } = opaque.client.startLogin({
      password,
    });

    this.addLog({
      actor: 'Client',
      step: '1. opaque.client.startLogin (Output)',
      description: 'Generated startLoginRequest and local clientLoginState.',
      details: {
        startLoginRequest,
        clientLoginState,
      },
      status: 'info',
    });

    this.addLog({
      actor: 'Network',
      step: '2. POST /login/start',
      description: 'Client sends username and startLoginRequest to the server.',
      details: {
        url: `${this.API_URL}/login/start`,
        body: { username, startLoginRequest },
      },
      status: 'info',
    });

    let startResponse: { loginSessionId: string; loginResponse: string };
    try {
      startResponse = await firstValueFrom(
        this.http.post<{ loginSessionId: string; loginResponse: string }>(
          `${this.API_URL}/login/start`,
          {
            username,
            startLoginRequest,
          }
        )
      );
    } catch (err: any) {
      this.addLog({
        actor: 'Server',
        step: 'Error /login/start',
        description: `Server returned error: ${err?.error?.error || err.message}`,
        details: err?.error || { message: err.message },
        status: 'error',
      });
      throw err;
    }

    this.addLog({
      actor: 'Server',
      step: '3. Response from /login/start',
      description: 'Server retrieved registrationRecord, computed loginResponse, and stored intermediate serverLoginState under loginSessionId.',
      details: {
        loginSessionId: startResponse.loginSessionId,
        loginResponse: startResponse.loginResponse,
      },
      status: 'info',
    });

    this.addLog({
      actor: 'Client',
      step: '4. opaque.client.finishLogin',
      description: 'Client verifies server loginResponse against password. If valid, computes shared sessionKey and cryptographic finishLoginRequest proof.',
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
      this.addLog({
        actor: 'Client',
        step: 'Error opaque.client.finishLogin',
        description: 'Invalid password or corrupted response. Client failed to authenticate.',
        details: { error: err.message },
        status: 'error',
      });
      throw err;
    }

    if (!clientLoginResult) {
      this.addLog({
        actor: 'Client',
        step: 'Error opaque.client.finishLogin',
        description: 'finishLogin returned empty result: invalid password.',
        status: 'error',
      });
      throw new Error('Client login failed: invalid password or corrupted credentials');
    }

    const { finishLoginRequest, sessionKey: clientSessionKey, exportKey, serverStaticPublicKey } =
      clientLoginResult;

    this.addLog({
      actor: 'Client',
      step: '4. opaque.client.finishLogin (Output)',
      description: 'Client computed sessionKey, exportKey, and finishLoginRequest proof.',
      details: {
        finishLoginRequest,
        clientSessionKey,
        exportKey,
        serverStaticPublicKey,
      },
      status: 'info',
    });

    this.addLog({
      actor: 'Network',
      step: '5. POST /login/finish',
      description: 'Client transmits finishLoginRequest proof and loginSessionId to server.',
      details: {
        url: `${this.API_URL}/login/finish`,
        body: {
          loginSessionId: startResponse.loginSessionId,
          finishLoginRequest,
        },
      },
      status: 'info',
    });

    let finishResponse: { success: boolean; message: string; sessionKey: string; username: string };
    try {
      finishResponse = await firstValueFrom(
        this.http.post<{ success: boolean; message: string; sessionKey: string; username: string }>(
          `${this.API_URL}/login/finish`,
          {
            loginSessionId: startResponse.loginSessionId,
            finishLoginRequest,
          }
        )
      );
    } catch (err: any) {
      this.addLog({
        actor: 'Server',
        step: 'Error /login/finish',
        description: `Server rejected proof: ${err?.error?.error || err.message}`,
        details: err?.error || { message: err.message },
        status: 'error',
      });
      throw err;
    }

    const keysMatch = finishResponse.sessionKey === clientSessionKey;

    this.addLog({
      actor: 'Server',
      step: '6. Login Verified by Server',
      description: `Server validated finishLoginRequest against serverLoginState. Session keys ${keysMatch ? 'MATCHED PERFECTLY' : 'MISMATCHED'}!`,
      details: {
        serverSessionKey: finishResponse.sessionKey,
        clientSessionKey: clientSessionKey,
        keysMatch,
      },
      status: keysMatch ? 'success' : 'error',
    });

    return {
      success: finishResponse.success,
      message: finishResponse.message,
      username: finishResponse.username,
      sessionKey: clientSessionKey,
      exportKey,
      serverStaticPublicKey,
    };
  }
}