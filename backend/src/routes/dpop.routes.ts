import express, { type Router, type Request, type Response, type NextFunction } from 'express';
import { dpopService } from '../services/dpop.service.ts';
import type {
  DPoPRegisterRequest,
  DPoPRegisterResponse,
  DPoPLoginRequest,
  DPoPLoginResponse,
  DPoPProtectedGetResponse,
  DPoPProtectedPostRequest,
  DPoPProtectedPostResponse,
  ErrorResponse,
} from '../types/index.ts';

const router: Router = express.Router();

function requireDPoPAuth(req: Request, res: Response, next: NextFunction) {
  const authHeader = req.header('Authorization');
  const dpopHeader = req.header('DPoP');

  try {
    const { user, jkt } = dpopService.validateAuth(authHeader, dpopHeader, req.method, req.baseUrl + req.path);
    (req as any).user = user;
    (req as any).jkt = jkt;
    next();
  } catch (err: any) {
    return res.status(err.statusCode || 401).json({ error: err.message });
  }
}

router.post('/register', (req: Request<{}, DPoPRegisterResponse | ErrorResponse, DPoPRegisterRequest>, res: Response<DPoPRegisterResponse | ErrorResponse>) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Missing username or password' });
  }

  try {
    const result = dpopService.register(req.body);
    return res.json(result);
  } catch (err: any) {
    return res.status(err.statusCode || 500).json({ error: err.message });
  }
});

router.post('/login', (req: Request<{}, DPoPLoginResponse | ErrorResponse, DPoPLoginRequest>, res: Response<DPoPLoginResponse | ErrorResponse>) => {
  const { username, password } = req.body;
  const dpopHeader = req.header('DPoP');

  if (!username || !password) {
    return res.status(400).json({ error: 'Missing username or password' });
  }

  try {
    const result = dpopService.login(req.body, dpopHeader);
    return res.json(result);
  } catch (err: any) {
    return res.status(err.statusCode || 500).json({ error: err.message });
  }
});

router.get('/protected/data', requireDPoPAuth, (req: Request<{}, DPoPProtectedGetResponse | ErrorResponse>, res: Response<DPoPProtectedGetResponse | ErrorResponse>) => {
  return res.json({
    success: true,
    method: 'DPoP',
    type: 'GET',
    message: 'Access granted via Proof-of-Possession (DPoP header + bound access token).',
    user: (req as any).user,
    timestamp: new Date().toISOString(),
    secretData: {
      vaultId: 'VLT-77182',
      permissions: ['read:sensitive', 'write:sensitive'],
      dpopBound: true,
    },
  });
});

router.post('/protected/data', requireDPoPAuth, (req: Request<{}, DPoPProtectedPostResponse | ErrorResponse, DPoPProtectedPostRequest>, res: Response<DPoPProtectedPostResponse | ErrorResponse>) => {
  return res.json({
    success: true,
    method: 'DPoP',
    type: 'POST',
    message: 'DPoP POST request verified against client private key signature.',
    user: (req as any).user,
    receivedPayload: req.body,
    timestamp: new Date().toISOString(),
  });
});

export default router;

