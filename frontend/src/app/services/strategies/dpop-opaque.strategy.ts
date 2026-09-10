import { Injectable } from '@angular/core';
import { AuthStrategy } from '../auth-strategy.interface';
import { AuthResult, ProtectedResponse } from '../auth.types';
import { ProtocolLoggerService } from '../logger.service';

@Injectable({
  providedIn: 'root',
})
export class DPoPOpaqueStrategy implements AuthStrategy {
  readonly id = 'dpop-opaque' as const;
  readonly name = 'DPoP + OPAQUE';
  readonly description =
    'Combines OPAQUE zero-knowledge password authentication with DPoP asymmetric Proof-of-Possession request binding.';

  constructor(private logger: ProtocolLoggerService) {}

  reset() {}

  async register(): Promise<AuthResult> {
    this.logger.addLog({
      actor: 'Client',
      step: 'DPoP + OPAQUE: Register',
      description: 'DPoP + OPAQUE is not implemented yet.',
      status: 'error',
    });
    throw new Error('DPoP + OPAQUE is not implemented yet.');
  }

  async login(): Promise<AuthResult> {
    this.logger.addLog({
      actor: 'Client',
      step: 'DPoP + OPAQUE: Login',
      description: 'DPoP + OPAQUE is not implemented yet.',
      status: 'error',
    });
    throw new Error('DPoP + OPAQUE is not implemented yet.');
  }

  async testProtectedGet(): Promise<ProtectedResponse> {
    this.logger.addLog({
      actor: 'Client',
      step: 'DPoP + OPAQUE: Protected GET',
      description: 'DPoP + OPAQUE is not implemented yet.',
      status: 'error',
    });
    throw new Error('DPoP + OPAQUE is not implemented yet.');
  }

  async testProtectedPost(): Promise<ProtectedResponse> {
    this.logger.addLog({
      actor: 'Client',
      step: 'DPoP + OPAQUE: Protected POST',
      description: 'DPoP + OPAQUE is not implemented yet.',
      status: 'error',
    });
    throw new Error('DPoP + OPAQUE is not implemented yet.');
  }
}
