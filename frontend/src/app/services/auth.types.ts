export type AuthMethod = 'opaque' | 'dpop' | 'dpop-opaque';

export interface LogEntry {
  id: number;
  time: string;
  actor: 'Client' | 'Server' | 'Network';
  step: string;
  description: string;
  headers?: Record<string, string>;
  body?: any;
  crypto?: Record<string, any>;
  details?: Record<string, any>;
  status: 'info' | 'success' | 'error';
}

export interface AuthResult {
  success: boolean;
  message: string;
  username?: string;
  sessionKey?: string;
  exportKey?: string;
  serverStaticPublicKey?: string;
  accessToken?: string;
  dpopThumbprint?: string;
  details?: Record<string, any>;
}

export interface ProtectedResponse {
  success: boolean;
  method: string;
  type: 'GET' | 'POST';
  message: string;
  user?: string;
  timestamp?: string;
  secretData?: Record<string, any>;
  receivedPayload?: any;
  [key: string]: any;
}

export * from './types';

