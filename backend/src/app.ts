import express, { type Express, type Request, type Response } from 'express';
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

function cleanExpiredSessions() {
  const now = Date.now();
  for (const [id, session] of loginSessions.entries()) {
    if (now - session.createdAt > 5 * 60 * 1000) {
      loginSessions.delete(id);
    }
  }
}
setInterval(cleanExpiredSessions, 60 * 1000);

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

const authRouter = express.Router();

authRouter.post('/register/start', (req: Request, res: Response) => {
  const { username, registrationRequest } = req.body;

  if (!username || !registrationRequest) {
    return res.status(400).json({ error: 'Missing username or registrationRequest' });
  }

  if (db.has(username)) {
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

  if (db.has(username)) {
    return res.status(409).json({ error: 'User already exists' });
  }

  try {
    db.set(username, { registrationRecord });
    return res.json({ success: true, message: 'User registered successfully' });
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
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
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

app.get('/', (req: Request, res: Response) => {
  res.send('OPAQUE backend is running');
});

startServer();