export interface DPoPOpaqueRegisterStartRequest {
  username: string;
  registrationRequest: string;
}

export interface DPoPOpaqueRegisterStartResponse {
  registrationResponse: string;
}

export interface DPoPOpaqueRegisterFinishRequest {
  username: string;
  registrationRecord: string;
}

export interface DPoPOpaqueRegisterFinishResponse {
  success: boolean;
  message: string;
}

export interface DPoPOpaqueLoginStartRequest {
  username: string;
  startLoginRequest: string;
}

export interface DPoPOpaqueLoginStartResponse {
  loginSessionId: string;
  loginResponse: string;
}

export interface DPoPOpaqueLoginFinishRequest {
  loginSessionId: string;
  finishLoginRequest: string;
}

export interface DPoPOpaqueLoginFinishResponse {
  success: boolean;
  message: string;
  username: string;
  accessToken: string;
}
