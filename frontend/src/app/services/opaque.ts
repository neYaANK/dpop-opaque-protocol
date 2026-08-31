import { Injectable } from '@angular/core';
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

/*
  1. startRegistration 
  2. post /registration/start
  3. finishRegistration
  4. post /registration/finish
*/
@Injectable({
  providedIn: 'root',
})
export class OpaqueService {
  private readonly API_URL = environment.apiUrl;

  constructor(private http: HttpClient) {}

  async register(username: string, password: string): Promise<RegisterResult> {

    const { clientRegistrationState, registrationRequest } = opaque.client.startRegistration({
      password,
    });

    const startResponse = await firstValueFrom(
      this.http.post<{ registrationResponse: string }>(`${this.API_URL}/register/start`, {
        username,
        registrationRequest,
      })
    );

    const { registrationRecord, exportKey, serverStaticPublicKey } =
      opaque.client.finishRegistration({
        clientRegistrationState,
        registrationResponse: startResponse.registrationResponse,
        password,
      });

    const finishResponse = await firstValueFrom(
      this.http.post<{ success: boolean; message: string }>(`${this.API_URL}/register/finish`, {
        username,
        registrationRecord,
      })
    );

    return {
      success: finishResponse.success,
      message: finishResponse.message,
      exportKey,
      serverStaticPublicKey,
    };
  }

/*
  1. startLogin
  2. post /login/start
  3. finishLogin
  4. post /login/finish
*/
  async login(username: string, password: string): Promise<LoginResult> {
    const { clientLoginState, startLoginRequest } = opaque.client.startLogin({
      password,
    });

    const startResponse = await firstValueFrom(
      this.http.post<{ loginSessionId: string; loginResponse: string }>(
        `${this.API_URL}/login/start`,
        {
          username,
          startLoginRequest,
        }
      )
    );

    const clientLoginResult = opaque.client.finishLogin({
      clientLoginState,
      loginResponse: startResponse.loginResponse,
      password,
    });

    if (!clientLoginResult) {
      throw new Error('Client login failed: invalid password or corrupted credentials');
    }

    const { finishLoginRequest, sessionKey: clientSessionKey, exportKey, serverStaticPublicKey } =
      clientLoginResult;

    const finishResponse = await firstValueFrom(
      this.http.post<{ success: boolean; message: string; sessionKey: string; username: string }>(
        `${this.API_URL}/login/finish`,
        {
          loginSessionId: startResponse.loginSessionId,
          finishLoginRequest,
        }
      )
    );

    if (finishResponse.sessionKey !== clientSessionKey) {
      console.warn('Session key differs between client and server');
    }

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