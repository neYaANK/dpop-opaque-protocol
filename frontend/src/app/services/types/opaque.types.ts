export interface OpaqueRegisterStartRequest {
  username: string;
  registrationRequest: string;
}

export interface OpaqueRegisterStartResponse {
  registrationResponse: string;
}

export interface OpaqueRegisterFinishRequest {
  username: string;
  registrationRecord: string;
}

export interface OpaqueRegisterFinishResponse {
  success: boolean;
  message: string;
}

export interface OpaqueLoginStartRequest {
  username: string;
  startLoginRequest: string;
}

export interface OpaqueLoginStartResponse {
  loginSessionId: string;
  loginResponse: string;
}

export interface OpaqueLoginFinishRequest {
  loginSessionId: string;
  finishLoginRequest: string;
}

export interface OpaqueLoginFinishResponse {
  success: boolean;
  message: string;
  username: string;
  accessToken: string;
}

