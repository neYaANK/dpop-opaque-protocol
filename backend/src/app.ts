import express, { type Express, type Request, type Response } from 'express';
import cors from 'cors';
import { opaqueService } from './services/opaque.service.ts';
import opaqueRouter from './routes/opaque.routes.ts';
import dpopRouter from './routes/dpop.routes.ts';
import dpopOpaqueRouter from './routes/dpop-opaque.routes.ts';

const app: Express = express();
const PORT = 8080;

app.use(cors());
app.use(express.json());

app.use('/api/opaque', opaqueRouter);
app.use('/api/dpop', dpopRouter);
app.use('/api/dpop-opaque', dpopOpaqueRouter);

app.get('/', (req: Request, res: Response) => {
  res.send('OPAQUE, DPoP & DPoP+OPAQUE backend is running');
});

async function startServer() {
  await opaqueService.init();
  app.listen(PORT, () => {
    console.log(`Server listening on http://localhost:${PORT}`);
  });
}

startServer();
