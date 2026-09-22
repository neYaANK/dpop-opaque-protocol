export interface OpaqueSecretData {
  accountNumber: string;
  balance: string;
  status: string;
}

export interface OpaqueProtectedGetResponse {
  success: boolean;
  method: 'OPAQUE';
  type: 'GET';
  message: string;
  user: string;
  timestamp: string;
  secretData: OpaqueSecretData;
}

export interface OpaqueProtectedPostRequest {
  [key: string]: any;
}

export interface OpaqueProtectedPostResponse {
  success: boolean;
  method: 'OPAQUE';
  type: 'POST';
  message: string;
  user: string;
  receivedPayload: any;
  timestamp: string;
}

export interface DPoPSecretData {
  vaultId: string;
  permissions: string[];
  dpopBound: boolean;
}

export interface DPoPProtectedGetResponse {
  success: boolean;
  method: 'DPoP';
  type: 'GET';
  message: string;
  user: string;
  timestamp: string;
  secretData: DPoPSecretData;
}

export interface DPoPProtectedPostRequest {
  [key: string]: any;
}

export interface DPoPProtectedPostResponse {
  success: boolean;
  method: 'DPoP';
  type: 'POST';
  message: string;
  user: string;
  receivedPayload: any;
  timestamp: string;
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
