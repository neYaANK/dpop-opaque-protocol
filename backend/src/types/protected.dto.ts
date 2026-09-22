export interface ErrorResponse {
  error: string;
}

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

