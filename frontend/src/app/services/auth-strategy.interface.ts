import { AuthMethod, AuthResult, ProtectedResponse } from './auth.types';

export interface AuthStrategy {
  readonly id: AuthMethod;
  readonly name: string;
  readonly description: string;

  register(username: string, password: string): Promise<AuthResult>;
  login(username: string, password: string): Promise<AuthResult>;
  testProtectedGet(): Promise<ProtectedResponse>;
  testProtectedPost(payload: any): Promise<ProtectedResponse>;
  reset(): void;
}
