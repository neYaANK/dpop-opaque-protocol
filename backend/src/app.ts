import express, { type Express, type Request, type Response, type NextFunction } from 'express';
import cors from 'cors';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import * as opaque from '@serenity-kit/opaque';
import { db } from './db.ts';

const app: Express = express();
const PORT = 8080;

app.use(cors());
app.use(express.json());

const SETUP_FILE = path.join(process.cwd(), '.server-setup');
let serverSetup: string;

interface LoginSession {
  serverLoginState: string;
  username: string;
  createdAt: number;
}
const loginSessions = new Map<string, LoginSession>();

interface ActiveOpaqueSession {
  username: string;
  sessionKey: string;
  createdAt: number;
}
const opaqueSessions = new Map<string, ActiveOpaqueSession>();

interface ActiveDPoPToken {
  username: string;
  jkt: string; // Thumbprint of client public key
  createdAt: number;
}
const dpopTokens = new Map<string, ActiveDPoPToken>();

function cleanExpiredSessions() {
  const now = Date.now();
  for (const [id, session] of loginSessions.entries()) {
    if (now - session.createdAt > 5 * 60 * 1000) {
      loginSessions.delete(id);
    }
  }
  for (const [key, session] of opaqueSessions.entries()) {
    if (now - session.createdAt > 24 * 60 * 60 * 1000) {
      opaqueSessions.delete(key);
    }
  }
  for (const [token, session] of dpopTokens.entries()) {
    if (now - session.createdAt > 24 * 60 * 60 * 1000) {
      dpopTokens.delete(token);
    }
  }
}
setInterval(cleanExpiredSessions, 60 * 1000);

function computeJwkThumbprint(jwk: { crv: string; kty: string; x: string; y: string }): string {
  const canonical = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y });
  return crypto.createHash('sha256').update(canonical).digest('base64url');
}

function verifyDPoPProof(
  dpopHeader: string | undefined,
  expectedMethod: string,
  expectedUrlPath: string
): { valid: boolean; jkt?: string; error?: string } {
  if (!dpopHeader) {
    return { valid: false, error: 'Missing DPoP header' };
  }

  try {
    const parts = dpopHeader.split('.');
    if (parts.length !== 3) {
      return { valid: false, error: 'Invalid DPoP JWT format' };
    }

    const [headerB64, payloadB64, sigB64] = parts;
    const header = JSON.parse(Buffer.from(headerB64, 'base64url').toString('utf-8'));
    const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf-8'));

    if (header.typ !== 'dpop+jwt' || header.alg !== 'ES256' || !header.jwk) {
      return { valid: false, error: 'Invalid DPoP header (expected typ: dpop+jwt, alg: ES256, jwk)' };
    }

    const jwk = header.jwk;
    if (jwk.kty !== 'EC' || jwk.crv !== 'P-256' || !jwk.x || !jwk.y) {
      return { valid: false, error: 'Invalid JWK in DPoP header' };
    }

    const now = Math.floor(Date.now() / 1000);
    if (!payload.iat || Math.abs(now - payload.iat) > 300) {
      return { valid: false, error: 'DPoP proof expired or timestamp skewed' };
    }

    if (payload.htm?.toUpperCase() !== expectedMethod.toUpperCase()) {
      return { valid: false, error: `DPoP htm mismatch (expected ${expectedMethod}, got ${payload.htm})` };
    }

    if (payload.htu && !payload.htu.includes(expectedUrlPath)) {
      return { valid: false, error: `DPoP htu mismatch (expected ${expectedUrlPath} in ${payload.htu})` };
    }

    const signingInput = Buffer.from(`${headerB64}.${payloadB64}`);
    const publicKey = crypto.createPublicKey({ key: jwk, format: 'jwk' });
    const signature = Buffer.from(sigB64, 'base64url');

    const isVerified = crypto.verify(
      'SHA256',
      signingInput,
      { key: publicKey, dsaEncoding: 'ieee-p1363' },
      signature
    );

    if (!isVerified) {
      return { valid: false, error: 'DPoP cryptographic signature verification failed' };
    }

    const jkt = computeJwkThumbprint(jwk);
    return { valid: true, jkt };
  } catch (err: any) {
    return { valid: false, error: `DPoP parsing error: ${err.message}` };
  }
}

async function startServer() {
  await opaque.ready;

  if (process.env.OPAQUE_SERVER_SETUP) {
    serverSetup = process.env.OPAQUE_SERVER_SETUP;
  } else if (fs.existsSync(SETUP_FILE)) {
    serverSetup = fs.readFileSync(SETUP_FILE, 'utf-8').trim();
    console.log('Loaded existing OPAQUE_SERVER_SETUP from .server-setup');
  } else {
    serverSetup = opaque.server.createSetup();
    fs.writeFileSync(SETUP_FILE, serverSetup, 'utf-8');
    console.log('Generated new OPAQUE_SERVER_SETUP and saved to .server-setup:');
    console.log(serverSetup);
  }

  app.listen(PORT, () => {
    console.log(`Server listening on http://localhost:${PORT}`);
  });
}

// ==========================================
// 1. OPAQUE Routes
// ==========================================
const authRouter = express.Router();

authRouter.post('/register/start', (req: Request, res: Response) => {
  const { username, registrationRequest } = req.body;

  if (!username || !registrationRequest) {
    return res.status(400).json({ error: 'Missing username or registrationRequest' });
  }

  if (db.has(username) && db.get(username)?.registrationRecord) {
    return res.status(409).json({ error: 'User already exists' });
  }

  try {
    const { registrationResponse } = opaque.server.createRegistrationResponse({
      serverSetup,
      userIdentifier: username,
      registrationRequest,
    });

    return res.json({ registrationResponse });
  } catch (err: any) {
    console.error('Register start error:', err);
    return res.status(500).json({ error: err.message });
  }
});

authRouter.post('/register/finish', (req: Request, res: Response) => {
  const { username, registrationRecord } = req.body;

  if (!username || !registrationRecord) {
    return res.status(400).json({ error: 'Missing username or registrationRecord' });
  }

  if (db.has(username) && db.get(username)?.registrationRecord) {
    return res.status(409).json({ error: 'User already exists' });
  }

  try {
    const existing = db.get(username) || {};
    db.set(username, { ...existing, registrationRecord });
    return res.json({ success: true, message: 'User registered successfully with OPAQUE' });
  } catch (err: any) {
    console.error('Register finish error:', err);
    return res.status(500).json({ error: err.message });
  }
});

authRouter.post('/login/start', (req: Request, res: Response) => {
  const { username, startLoginRequest } = req.body;

  if (!username || !startLoginRequest) {
    return res.status(400).json({ error: 'Missing username or startLoginRequest' });
  }

  const user = db.get(username);
  if (!user || !user.registrationRecord) {
    return res.status(404).json({ error: 'User not found or not registered with OPAQUE' });
  }

  try {
    const { loginResponse, serverLoginState } = opaque.server.startLogin({
      userIdentifier: username,
      registrationRecord: user.registrationRecord,
      serverSetup,
      startLoginRequest,
    });

    const loginSessionId = crypto.randomUUID();
    loginSessions.set(loginSessionId, {
      serverLoginState,
      username,
      createdAt: Date.now(),
    });

    return res.json({ loginSessionId, loginResponse });
  } catch (err: any) {
    console.error('Login start error:', err);
    return res.status(500).json({ error: err.message });
  }
});

authRouter.post('/login/finish', (req: Request, res: Response) => {
  const { loginSessionId, finishLoginRequest } = req.body;

  if (!loginSessionId || !finishLoginRequest) {
    return res.status(400).json({ error: 'Missing loginSessionId or finishLoginRequest' });
  }

  const session = loginSessions.get(loginSessionId);
  if (!session) {
    return res.status(400).json({ error: 'Invalid or expired login session' });
  }

  loginSessions.delete(loginSessionId);

  try {
    const { sessionKey } = opaque.server.finishLogin({
      finishLoginRequest,
      serverLoginState: session.serverLoginState,
    });

    opaqueSessions.set(sessionKey, {
      username: session.username,
      sessionKey,
      createdAt: Date.now(),
    });

    return res.json({
      success: true,
      message: 'Login successful',
      username: session.username,
      sessionKey,
    });
  } catch (err: any) {
    console.error('Login finish error:', err);
    return res.status(401).json({ error: 'Authentication failed' });
  }
});

app.use('/api/auth', authRouter);

// ==========================================
// 2. DPoP Routes
// ==========================================
const dpopRouter = express.Router();

dpopRouter.post('/register', (req: Request, res: Response) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Missing username or password' });
  }

  if (db.has(username) && db.get(username)?.passwordHash) {
    return res.status(409).json({ error: 'User already exists' });
  }

  const passwordHash = crypto.createHash('sha256').update(password).digest('hex');
  const existing = db.get(username) || {};
  db.set(username, { ...existing, passwordHash });

  return res.json({ success: true, message: 'User registered successfully with DPoP credentials' });
});

dpopRouter.post('/login', (req: Request, res: Response) => {
  const { username, password } = req.body;
  const dpopHeader = req.header('DPoP');

  if (!username || !password) {
    return res.status(400).json({ error: 'Missing username or password' });
  }

  const user = db.get(username);
  if (!user || !user.passwordHash) {
    return res.status(404).json({ error: 'User not found or not registered with DPoP' });
  }

  const hash = crypto.createHash('sha256').update(password).digest('hex');
  if (user.passwordHash !== hash) {
    return res.status(401).json({ error: 'Invalid password' });
  }

  const dpopVerification = verifyDPoPProof(dpopHeader, 'POST', '/api/dpop/login');
  if (!dpopVerification.valid || !dpopVerification.jkt) {
    return res.status(400).json({ error: `DPoP verification failed: ${dpopVerification.error}` });
  }

  const accessToken = 'dpop_token_' + crypto.randomUUID();
  dpopTokens.set(accessToken, {
    username,
    jkt: dpopVerification.jkt,
    createdAt: Date.now(),
  });

  return res.json({
    success: true,
    message: 'DPoP login successful. Token bound to public key thumbprint.',
    username,
    accessToken,
    dpopThumbprint: dpopVerification.jkt,
  });
});

app.use('/api/dpop', dpopRouter);

// ==========================================
// 3. Protected Endpoints (OPAQUE & DPoP)
// ==========================================
const protectedRouter = express.Router();

function requireOpaqueAuth(req: Request, res: Response, next: NextFunction) {
  const authHeader = req.header('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized: Missing or malformed Bearer sessionKey header' });
  }

  const sessionKey = authHeader.slice(7).trim();
  const session = opaqueSessions.get(sessionKey);
  if (!session) {
    return res.status(401).json({ error: 'Unauthorized: Invalid or expired OPAQUE session' });
  }

  (req as any).user = session.username;
  (req as any).sessionKey = sessionKey;
  next();
}

function requireDPoPAuth(req: Request, res: Response, next: NextFunction) {
  const authHeader = req.header('Authorization');
  const dpopHeader = req.header('DPoP');

  if (!authHeader || !authHeader.startsWith('DPoP ')) {
    return res.status(401).json({ error: 'Unauthorized: Missing or malformed Authorization: DPoP <token> header' });
  }

  const token = authHeader.slice(5).trim();
  const tokenRecord = dpopTokens.get(token);
  if (!tokenRecord) {
    return res.status(401).json({ error: 'Unauthorized: Invalid or expired DPoP access token' });
  }

  const dpopVerification = verifyDPoPProof(dpopHeader, req.method, req.baseUrl + req.path);
  if (!dpopVerification.valid) {
    return res.status(401).json({ error: `DPoP proof invalid: ${dpopVerification.error}` });
  }

  if (dpopVerification.jkt !== tokenRecord.jkt) {
    return res.status(401).json({
      error: 'DPoP key binding mismatch: Proof key does not match token thumbprint (Proof-of-Possession failed)',
    });
  }

  (req as any).user = tokenRecord.username;
  (req as any).jkt = tokenRecord.jkt;
  next();
}

protectedRouter.get('/opaque/data', requireOpaqueAuth, (req: Request, res: Response) => {
  return res.json({
    success: true,
    method: 'OPAQUE',
    type: 'GET',
    message: 'Access granted to confidential resource via OPAQUE shared session key.',
    user: (req as any).user,
    timestamp: new Date().toISOString(),
    secretData: {
      accountNumber: 'ACC-9842104',
      balance: '$12,450.00',
      status: 'Active / Verified',
    },
  });
});

protectedRouter.post('/opaque/data', requireOpaqueAuth, (req: Request, res: Response) => {
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

protectedRouter.get('/dpop/data', requireDPoPAuth, (req: Request, res: Response) => {
  return res.json({
    success: true,
    method: 'DPoP',
    type: 'GET',
    message: 'Access granted via Proof-of-Possession (DPoP header + bound access token).',
    user: (req as any).user,
    dpopThumbprint: (req as any).jkt,
    timestamp: new Date().toISOString(),
    secretData: {
      vaultId: 'VLT-77182',
      permissions: ['read:sensitive', 'write:sensitive'],
      dpopBound: true,
    },
  });
});

protectedRouter.post('/dpop/data', requireDPoPAuth, (req: Request, res: Response) => {
  return res.json({
    success: true,
    method: 'DPoP',
    type: 'POST',
    message: 'DPoP POST request verified against client private key signature.',
    user: (req as any).user,
    dpopThumbprint: (req as any).jkt,
    receivedPayload: req.body,
    timestamp: new Date().toISOString(),
  });
});

app.use('/api/protected', protectedRouter);

app.get('/', (req: Request, res: Response) => {
  res.send('OPAQUE & DPoP backend is running');
});

startServer();