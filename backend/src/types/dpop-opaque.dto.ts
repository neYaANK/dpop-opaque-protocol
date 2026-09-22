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

export interface DPoPOpaqueSecretData {
  vaultId: string;
  accountNumber: string;
  permissions: string[];
  dpopBound: boolean;
  opaqueEncrypted: boolean;
}

export interface DPoPOpaqueProtectedGetResponse {
  success: boolean;
  method: 'DPoP + OPAQUE';
  type: 'GET';
  message: string;
  user: string;
  timestamp: string;
  secretData: DPoPOpaqueSecretData;
}

export interface DPoPOpaqueProtectedPostRequest {
  [key: string]: any;
}

export interface DPoPOpaqueProtectedPostResponse {
  success: boolean;
  method: 'DPoP + OPAQUE';
  type: 'POST';
  message: string;
  user: string;
  receivedPayload: any;
  timestamp: string;
}

