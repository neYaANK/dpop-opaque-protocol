import { Injectable, computed, signal } from '@angular/core';
import { AuthMethod, AuthResult, ProtectedResponse } from './auth.types';
import { AuthStrategy } from './auth-strategy.interface';
import { OpaqueStrategy } from './strategies/opaque.strategy';
import { DPoPStrategy } from './strategies/dpop.strategy';
import { DPoPOpaqueStrategy } from './strategies/dpop-opaque.strategy';
import { ProtocolLoggerService } from './logger.service';

@Injectable({
  providedIn: 'root',
})
export class AuthService {
  readonly selectedMethod = signal<AuthMethod>('opaque');

  readonly availableMethods: { id: AuthMethod; name: string; description: string }[] = [
    {
      id: 'opaque',
      name: 'OPAQUE',
      description: 'Zero-knowledge password handshake.',
    },
    {
      id: 'dpop',
      name: 'DPoP',
      description: 'Asymmetric Proof-of-Possession tokens bound to ECDSA key pair.',
    },
    {
      id: 'dpop-opaque',
      name: 'DPoP + OPAQUE',
      description: 'Hybrid combining OPAQUE handshake with DPoP request binding.',
    },
  ];

  private readonly strategies: Record<AuthMethod, AuthStrategy>;

  readonly currentStrategy = computed(() => this.strategies[this.selectedMethod()]);

  get logs() {
    return this.logger.logs;
  }

  constructor(
    private opaqueStrategy: OpaqueStrategy,
    private dpopStrategy: DPoPStrategy,
    private dpopOpaqueStrategy: DPoPOpaqueStrategy,
    private logger: ProtocolLoggerService
  ) {
    this.strategies = {
      'opaque': this.opaqueStrategy,
      'dpop': this.dpopStrategy,
      'dpop-opaque': this.dpopOpaqueStrategy,
    };
  }

  setMethod(method: AuthMethod) {
    this.selectedMethod.set(method);
    this.logger.addLog({
      actor: 'Client',
      step: 'Security Method Switched',
      description: `Active security provider changed to: ${this.currentStrategy().name}`,
      details: {
        method: this.currentStrategy().id,
      },
      status: 'info',
    });
  }

  clearLogs() {
    this.logger.clearLogs();
  }

  async register(username: string, password: string): Promise<AuthResult> {
    return this.currentStrategy().register(username, password);
  }

  async login(username: string, password: string): Promise<AuthResult> {
    return this.currentStrategy().login(username, password);
  }

  async testProtectedGet(): Promise<ProtectedResponse> {
    return this.currentStrategy().testProtectedGet();
  }

  async testProtectedPost(payload: any): Promise<ProtectedResponse> {
    return this.currentStrategy().testProtectedPost(payload);
  }
}
