import { opaqueService } from './opaque.service.ts';
import { dpopService } from './dpop.service.ts';
import { jwtService } from './jwt.service.ts';
import type {
  DPoPOpaqueRegisterStartRequest,
  DPoPOpaqueRegisterStartResponse,
  DPoPOpaqueRegisterFinishRequest,
  DPoPOpaqueRegisterFinishResponse,
  DPoPOpaqueLoginStartRequest,
  DPoPOpaqueLoginStartResponse,
  DPoPOpaqueLoginFinishRequest,
  DPoPOpaqueLoginFinishResponse,
} from '../types/index.ts';

class DPoPOpaqueService {
  registerStart(data: DPoPOpaqueRegisterStartRequest): DPoPOpaqueRegisterStartResponse {
    return opaqueService.registerStart(data);
  }

  registerFinish(data: DPoPOpaqueRegisterFinishRequest): DPoPOpaqueRegisterFinishResponse {
    const res = opaqueService.registerFinish(data);
    return { success: res.success, message: 'User registered successfully with DPoP+OPAQUE' };
  }

  loginStart(data: DPoPOpaqueLoginStartRequest): DPoPOpaqueLoginStartResponse {
    return opaqueService.loginStart(data);
  }

  loginFinish(data: DPoPOpaqueLoginFinishRequest, dpopHeader?: string): DPoPOpaqueLoginFinishResponse {
    const dpopVerification = dpopService.verifyDPoPProof(dpopHeader, 'POST', '/api/dpop-opaque/login/finish');
    if (!dpopVerification.valid || !dpopVerification.jkt) {
      const error: any = new Error(`DPoP verification failed: ${dpopVerification.error}`);
      error.statusCode = 400;
      throw error;
    }

    const { username } = opaqueService.finishOpaqueLoginHandshake(
      data.loginSessionId,
      data.finishLoginRequest
    );

    const accessToken = jwtService.mintAccessToken(username, {
      jkt: dpopVerification.jkt,
      authMethod: 'opaque+dpop',
    });

    return {
      success: true,
      message: 'DPoP + OPAQUE login successful. Token bound to public key thumbprint and authenticated via OPAQUE.',
      username,
      accessToken,
    };
  }

  validateAuth(
    authHeader: string | undefined,
    dpopHeader: string | undefined,
    method: string,
    urlPath: string
  ): { user: string; jkt: string } {
    return dpopService.validateAuth(authHeader, dpopHeader, method, urlPath);
  }
}

export const dpopOpaqueService = new DPoPOpaqueService();
