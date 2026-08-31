import express, { type Express, type Request, type Response } from 'express';
import * as opaque from '@serenity-kit/opaque';
import { db } from './db.ts';
const app: Express = express();
const PORT = 8080;
const OPAQUE_KEY = process.env.OPAQUE_SERVER_SETUP || null;
let serverSetup: string;


async function startServer() {
  await opaque.ready;

  if (OPAQUE_KEY) {
    serverSetup = OPAQUE_KEY;
  } else {
    serverSetup = opaque.server.createSetup();
    console.log('Generated NEW OPAQUE_SERVER_SETUP. Save this to .env for future use:');
    console.log(serverSetup);
  }
  app.listen(PORT, () => {
    console.log(`Server listening on http://localhost:${PORT}`);
  });
}

app.get('/', (req: Request, res: Response) => {
  res.send('Hello World!');
});

app.post('/register/start', (req: Request, res: Response) => {
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

startServer();