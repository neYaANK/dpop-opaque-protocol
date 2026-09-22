import express, { type Router, type Request, type Response, type NextFunction } from 'express';
import { opaqueService } from '../services/opaque.service.ts';
import type {
  OpaqueRegisterStartRequest,
  OpaqueRegisterStartResponse,
  OpaqueRegisterFinishRequest,
  OpaqueRegisterFinishResponse,
  OpaqueLoginStartRequest,
  OpaqueLoginStartResponse,
  OpaqueLoginFinishRequest,
  OpaqueLoginFinishResponse,
  OpaqueProtectedGetResponse,
  OpaqueProtectedPostRequest,
  OpaqueProtectedPostResponse,
  ErrorResponse,
} from '../types/index.ts';

const router: Router = express.Router();

function requireOpaqueAuth(req: Request, res: Response, next: NextFunction) {
  const authHeader = req.header('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized: Missing or malformed Bearer token' });
  }

  const token = authHeader.slice(7).trim();
  try {
    const user = opaqueService.validateToken(token);
    (req as any).user = user;
    next();
  } catch (err: any) {
    return res.status(err.statusCode || 401).json({ error: err.message });
  }
}

router.post('/register/start', (req: Request<{}, OpaqueRegisterStartResponse | ErrorResponse, OpaqueRegisterStartRequest>, res: Response<OpaqueRegisterStartResponse | ErrorResponse>) => {
  const { username, registrationRequest } = req.body;
  if (!username || !registrationRequest) {
    return res.status(400).json({ error: 'Missing username or registrationRequest' });
  }

  try {
    const result = opaqueService.registerStart(req.body);
    return res.json(result);
  } catch (err: any) {
    return res.status(err.statusCode || 500).json({ error: err.message });
  }
});

router.post('/register/finish', (req: Request<{}, OpaqueRegisterFinishResponse | ErrorResponse, OpaqueRegisterFinishRequest>, res: Response<OpaqueRegisterFinishResponse | ErrorResponse>) => {
  const { username, registrationRecord } = req.body;
  if (!username || !registrationRecord) {
    return res.status(400).json({ error: 'Missing username or registrationRecord' });
  }

  try {
    const result = opaqueService.registerFinish(req.body);
    return res.json(result);
  } catch (err: any) {
    return res.status(err.statusCode || 500).json({ error: err.message });
  }
});

router.post('/login/start', (req: Request<{}, OpaqueLoginStartResponse | ErrorResponse, OpaqueLoginStartRequest>, res: Response<OpaqueLoginStartResponse | ErrorResponse>) => {
  const { username, startLoginRequest } = req.body;
  if (!username || !startLoginRequest) {
    return res.status(400).json({ error: 'Missing username or startLoginRequest' });
  }

  try {
    const result = opaqueService.loginStart(req.body);
    return res.json(result);
  } catch (err: any) {
    return res.status(err.statusCode || 500).json({ error: err.message });
  }
});

router.post('/login/finish', (req: Request<{}, OpaqueLoginFinishResponse | ErrorResponse, OpaqueLoginFinishRequest>, res: Response<OpaqueLoginFinishResponse | ErrorResponse>) => {
  const { loginSessionId, finishLoginRequest } = req.body;
  if (!loginSessionId || !finishLoginRequest) {
    return res.status(400).json({ error: 'Missing loginSessionId or finishLoginRequest' });
  }

  try {
    const result = opaqueService.loginFinish(req.body);
    return res.json(result);
  } catch (err: any) {
    return res.status(err.statusCode || 401).json({ error: err.message });
  }
});

router.get('/protected/data', requireOpaqueAuth, (req: Request<{}, OpaqueProtectedGetResponse | ErrorResponse>, res: Response<OpaqueProtectedGetResponse | ErrorResponse>) => {
  return res.json({
    success: true,
    method: 'OPAQUE',
    type: 'GET',
    message: 'Access granted to confidential resource via OPAQUE authenticated access token.',
    user: (req as any).user,
    timestamp: new Date().toISOString(),
    secretData: {
      accountNumber: 'ACC-9842104',
      balance: '$12,450.00',
      status: 'Active / Verified',
    },
  });
});

router.post('/protected/data', requireOpaqueAuth, (req: Request<{}, OpaqueProtectedPostResponse | ErrorResponse, OpaqueProtectedPostRequest>, res: Response<OpaqueProtectedPostResponse | ErrorResponse>) => {
  return res.json({
    success: true,
    method: 'OPAQUE',
    type: 'POST',
    message: 'Data successfully processed on protected server endpoint via OPAQUE.',
    user: (req as any).user,
    receivedPayload: req.body,
    timestamp: new Date().toISOString(),
  });
});

export default router;

