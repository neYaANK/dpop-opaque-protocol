import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import * as opaque from '@serenity-kit/opaque';
import { firstValueFrom } from 'rxjs';
import { environment } from '../../environments/environment';

@Injectable({
  providedIn: 'root',
})
export class OpaqueService {
  private readonly API_URL = environment.apiUrl;

  constructor(private http: HttpClient){}

  async startRegistrationFlow(username: string, password: string) {
    const { clientRegistrationState, registrationRequest } = opaque.client.startRegistration({
      password,
    });

    const response = await firstValueFrom(
      this.http.post<{ registrationResponse: string }>(`${this.API_URL}/register/start`, {
        username,
        registrationRequest,
      })
    );

    const { registrationResponse } = response;

    // clientRegistrationState и registrationResponse пойдут в следующий финальный шаг регистрации
    return { clientRegistrationState, registrationResponse };
  }

  async finishRegistrationFlow(clientRegistrationState: string, registrationResponse: string, password: string) {
    
    const {registrationRecord} = opaque.client.finishRegistration({
      clientRegistrationState,
      registrationResponse,
      password,
    });
   
    
    return { registrationRecord };
  }

}