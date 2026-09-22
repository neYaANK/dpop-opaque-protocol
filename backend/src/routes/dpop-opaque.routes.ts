import express, { type Router, type Request, type Response, type NextFunction } from 'express';
import { dpopOpaqueService } from '../services/dpop-opaque.service.ts';
import type {
  DPoPOpaqueRegisterStartRequest,
  DPoPOpaqueRegisterStartResponse,
  DPoPOpaqueRegisterFinishRequest,
  DPoPOpaqueRegisterFinishResponse,
  DPoPOpaqueLoginStartRequest,
  DPoPOpaqueLoginStartResponse,
  DPoPOpaqueLoginFinishRequest,
  DPoPOpaqueLoginFinishResponse,
  DPoPOpaqueProtectedGetResponse,
  DPoPOpaqueProtectedPostRequest,
  DPoPOpaqueProtectedPostResponse,
  ErrorResponse,
} from '../types/index.ts';

const router: Router = express.Router();

function requireDPoPOpaqueAuth(req: Request, res: Response, next: NextFunction) {
  const authHeader = req.header('Authorization');
  const dpopHeader = req.header('DPoP');

  try {
    const { user, jkt } = dpopOpaqueService.validateAuth(authHeader, dpopHeader, req.method, req.baseUrl + req.path);
    (req as any).user = user;
    (req as any).jkt = jkt;
    next();
  } catch (err: any) {
    return res.status(err.statusCode || 401).json({ error: err.message });
  }
}

router.post('/register/start', (req: Request<{}, DPoPOpaqueRegisterStartResponse | ErrorResponse, DPoPOpaqueRegisterStartRequest>, res: Response<DPoPOpaqueRegisterStartResponse | ErrorResponse>) => {
  const { username, registrationRequest } = req.body;
  if (!username || !registrationRequest) {
    return res.status(400).json({ error: 'Missing username or registrationRequest' });
  }

  try {
    const result = dpopOpaqueService.registerStart(req.body);
    return res.json(result);
  } catch (err: any) {
    return res.status(err.statusCode || 500).json({ error: err.message });
  }
});

router.post('/register/finish', (req: Request<{}, DPoPOpaqueRegisterFinishResponse | ErrorResponse, DPoPOpaqueRegisterFinishRequest>, res: Response<DPoPOpaqueRegisterFinishResponse | ErrorResponse>) => {
  const { username, registrationRecord } = req.body;
  if (!username || !registrationRecord) {
    return res.status(400).json({ error: 'Missing username or registrationRecord' });
  }

  try {
    const result = dpopOpaqueService.registerFinish(req.body);
    return res.json(result);
  } catch (err: any) {
    return res.status(err.statusCode || 500).json({ error: err.message });
  }
});

router.post('/login/start', (req: Request<{}, DPoPOpaqueLoginStartResponse | ErrorResponse, DPoPOpaqueLoginStartRequest>, res: Response<DPoPOpaqueLoginStartResponse | ErrorResponse>) => {
  const { username, startLoginRequest } = req.body;
  if (!username || !startLoginRequest) {
    return res.status(400).json({ error: 'Missing username or startLoginRequest' });
  }

  try {
    const result = dpopOpaqueService.loginStart(req.body);
    return res.json(result);
  } catch (err: any) {
    return res.status(err.statusCode || 500).json({ error: err.message });
  }
});

router.post('/login/finish', (req: Request<{}, DPoPOpaqueLoginFinishResponse | ErrorResponse, DPoPOpaqueLoginFinishRequest>, res: Response<DPoPOpaqueLoginFinishResponse | ErrorResponse>) => {
  const { loginSessionId, finishLoginRequest } = req.body;
  const dpopHeader = req.header('DPoP');

  if (!loginSessionId || !finishLoginRequest) {
    return res.status(400).json({ error: 'Missing loginSessionId or finishLoginRequest' });
  }

  try {
    const result = dpopOpaqueService.loginFinish(req.body, dpopHeader);
    return res.json(result);
  } catch (err: any) {
    return res.status(err.statusCode || 401).json({ error: err.message });
  }
});

router.get('/protected/data', requireDPoPOpaqueAuth, (req: Request<{}, DPoPOpaqueProtectedGetResponse | ErrorResponse>, res: Response<DPoPOpaqueProtectedGetResponse | ErrorResponse>) => {
  return res.json({
    success: true,
    method: 'DPoP + OPAQUE',
    type: 'GET',
    message: 'Access granted via DPoP Proof-of-Possession and OPAQUE mutual authentication.',
    user: (req as any).user,
    timestamp: new Date().toISOString(),
    secretData: {
      vaultId: 'VLT-DPOP-OPAQUE-900',
      accountNumber: 'ACC-HYBRID-8812',
      permissions: ['read:all', 'write:all', 'admin:secure'],
      dpopBound: true,
      opaqueEncrypted: true,
    },
  });
});

router.post('/protected/data', requireDPoPOpaqueAuth, (req: Request<{}, DPoPOpaqueProtectedPostResponse | ErrorResponse, DPoPOpaqueProtectedPostRequest>, res: Response<DPoPOpaqueProtectedPostResponse | ErrorResponse>) => {
  return res.json({
    success: true,
    method: 'DPoP + OPAQUE',
    type: 'POST',
    message: 'DPoP + OPAQUE POST request authenticated and verified.',
    user: (req as any).user,
    receivedPayload: req.body,
    timestamp: new Date().toISOString(),
  });
});

export default router;

