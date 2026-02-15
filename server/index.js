import express from 'express';
import cors from 'cors';
import { scanTarget } from './scanner.js';

const app = express();
const PORT = 3001;

app.use(cors());
app.use(express.json());

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', message: 'AEGIS Scanner Backend Active' });
});

// Main scanning endpoint
app.post('/api/scan', async (req, res) => {
  const { targetUrl, vulnType, payload } = req.body;

  if (!targetUrl) {
    return res.status(400).json({ error: 'Target URL is required' });
  }

  console.log(`[SCAN] Starting ${vulnType} scan on: ${targetUrl}`);
  console.log(`[SCAN] Payload: ${payload}`);

  try {
    const result = await scanTarget({ targetUrl, vulnType, payload });
    console.log(`[SCAN] Completed: ${result.vulnerability_found ? 'VULNERABLE' : 'SECURE'}`);
    res.json(result);
  } catch (error) {
    console.error(`[SCAN] Error: ${error.message}`);
    res.status(500).json({ error: error.message });
  }
});

app.listen(PORT, () => {
  console.log(`
╔═══════════════════════════════════════════════════════════╗
║           AEGIS AI PENTEST AGENT - BACKEND                ║
║                                                           ║
║  ⚠️  WARNING: Use only on systems you have permission     ║
║     to test. Unauthorized testing is illegal.             ║
║                                                           ║
║  Server running on: http://localhost:${PORT}                 ║
╚═══════════════════════════════════════════════════════════╝
  `);
});
