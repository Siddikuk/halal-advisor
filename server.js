require('dotenv').config();
const express = require('express');
const path = require('path');
const Anthropic = require('@anthropic-ai/sdk');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ─────────────────────────────────────────────
// DATABASE & AUTH
// ─────────────────────────────────────────────

const db = new Database(path.join(__dirname, 'halal_advisor.db'));
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    email        TEXT    UNIQUE NOT NULL COLLATE NOCASE,
    password_hash TEXT   NOT NULL,
    trial_start  INTEGER NOT NULL,
    created_at   INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS user_data (
    user_id    INTEGER NOT NULL,
    data_key   TEXT    NOT NULL,
    data_value TEXT    NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (user_id, data_key),
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
`);

const JWT_SECRET = process.env.JWT_SECRET || 'halal-advisor-dev-secret-change-in-production';
const TRIAL_DAYS = 14;

function trialDaysLeft(trialStart) {
  return Math.max(0, TRIAL_DAYS - Math.floor((Date.now() - trialStart) / 86400000));
}

function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth?.startsWith('Bearer ')) return res.status(401).json({ error: 'Authentication required. Please log in.' });
  try {
    req.user = jwt.verify(auth.slice(7), JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Session expired. Please log in again.' });
  }
}

// POST /api/auth/signup
app.post('/api/auth/signup', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required.' });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: 'Invalid email address.' });
  if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  try {
    const hash = await bcrypt.hash(password, 12);
    const now = Date.now();
    const result = db.prepare(
      'INSERT INTO users (email, password_hash, trial_start, created_at) VALUES (?, ?, ?, ?)'
    ).run(email.toLowerCase(), hash, now, now);
    const token = jwt.sign({ userId: result.lastInsertRowid, email: email.toLowerCase() }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, email: email.toLowerCase(), trialDaysLeft: TRIAL_DAYS });
  } catch (err) {
    if (err.message.includes('UNIQUE constraint')) return res.status(409).json({ error: 'This email is already registered. Please sign in.' });
    console.error('[signup]', err.message);
    res.status(500).json({ error: 'Registration failed. Please try again.' });
  }
});

// POST /api/auth/login
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required.' });
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email.toLowerCase());
  if (!user) return res.status(401).json({ error: 'Invalid email or password.' });
  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) return res.status(401).json({ error: 'Invalid email or password.' });
  const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, email: user.email, trialDaysLeft: trialDaysLeft(user.trial_start) });
});

// GET /api/user/me
app.get('/api/user/me', authMiddleware, (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.userId);
  if (!user) return res.status(404).json({ error: 'User not found.' });
  res.json({ email: user.email, trialDaysLeft: trialDaysLeft(user.trial_start) });
});

// GET /api/user/data — load all user data keys
app.get('/api/user/data', authMiddleware, (req, res) => {
  const rows = db.prepare('SELECT data_key, data_value FROM user_data WHERE user_id = ?').all(req.user.userId);
  const result = {};
  for (const row of rows) {
    try { result[row.data_key] = JSON.parse(row.data_value); } catch { result[row.data_key] = row.data_value; }
  }
  res.json(result);
});

// PUT /api/user/data — save one data key
app.put('/api/user/data', authMiddleware, (req, res) => {
  const { key, value } = req.body;
  if (!key) return res.status(400).json({ error: 'Data key required.' });
  db.prepare(
    'INSERT OR REPLACE INTO user_data (user_id, data_key, data_value, updated_at) VALUES (?, ?, ?, ?)'
  ).run(req.user.userId, key, JSON.stringify(value), Date.now());
  res.json({ ok: true });
});

// ─────────────────────────────────────────────
// MADHAB-SPECIFIC SYSTEM PROMPTS
// ─────────────────────────────────────────────

const MADHAB_NAMES = {
  shafii:  "Shafi'i (الشافعي)",
  hanafi:  "Hanafi (الحنفي)",
  maliki:  "Maliki (المالكي)",
  hanbali: "Hanbali (الحنبلي)"
};

const MADHAB_ZAKAT_RULES = {
  shafii: `
ZAKAT RULES — SHAFI'I MADHAB (إمام الشافعي)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
- Nisab: GOLD standard only = 85 grams of gold (NOT silver — Shafi'i does not use silver nisab)
- Zakat rate: 2.5% on all zakatable wealth above nisab
- Hawl: Wealth must be held for one complete lunar year (354 days)
- Debts: In Shafi'i madhab, debts do NOT reduce zakatable wealth. You owe zakat on the full amount regardless of any debts you carry. This differs from the other three madhabs.
- Zakatable assets: Cash, savings, gold/silver above nisab, business inventory, halal shares, receivables
- Gold jewellery: Zakat is due if total gold exceeds 85g nisab. Women's personal-use jewellery within customary amounts may be exempt per some Shafi'i scholars — always consult a scholar on this.
- Zakat al-Fitr: ~£5–10 per household member (2.5kg staple food equivalent)`,

  hanafi: `
ZAKAT RULES — HANAFI MADHAB (إمام أبو حنيفة)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
- Nisab: Based on the LOWER of: 612.36g of silver (approx. £441 at current prices) OR 87.48g of gold (~£6,560). In practice, the silver nisab is almost always lower, so most Hanafi Muslims use the silver threshold — this means MORE people qualify to pay zakat, which benefits the poor.
- Zakat rate: 2.5% on all zakatable wealth above nisab
- Hawl: One complete lunar year (354 days) from when wealth first reaches nisab
- Debts: In Hanafi madhab, debts CAN be deducted from zakatable wealth before calculating zakat. Subtract personal debts (excluding long-term mortgages on primary residence) from your total assets.
- Zakatable assets: Cash, savings, gold/silver, business inventory, trade goods, receivables, halal shares
- Gold jewellery: Women's personal-use gold jewellery is EXEMPT from zakat in the Hanafi madhab. This is a unique Hanafi ruling based on the principle of 'urf (customary practice). Investment gold is still zakatable.
- Zakat al-Fitr: ~£5–10 per household member (2.5kg staple food equivalent), paid before Eid al-Fitr prayer`,

  maliki: `
ZAKAT RULES — MALIKI MADHAB (إمام مالك)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
- Nisab: 20 dinars = 85 grams of gold (gold standard, similar to Shafi'i and Hanbali). Some Maliki scholars also reference 200 dirhams = 595g silver for silver-specific calculations.
- Zakat rate: 2.5% on all zakatable wealth above nisab
- Hawl: One complete lunar year (354 days). Importantly in Maliki madhab, if wealth drops below nisab during the year but returns to nisab at the year-end, the year continues (does not reset) — only if it drops to zero does the hawl fully reset.
- Debts: In Maliki madhab, debts of immediate necessity CAN be deducted from zakatable wealth. Long-term debts (e.g. mortgages) are treated more carefully — consult a scholar.
- Zakatable assets: Cash, savings, gold/silver, business inventory, halal shares, livestock, agricultural produce
- Gold jewellery: Personal adornment jewellery worn regularly is EXEMPT from zakat in the Maliki madhab (this is the Maliki and Hanafi position, distinct from Shafi'i and the stronger Hanbali opinion).
- Agricultural produce: Zakat al-Zuru' applies — 10% on rain-fed crops, 5% on irrigated crops, no hawl required
- Zakat al-Fitr: ~£5–10 per household member`,

  hanbali: `
ZAKAT RULES — HANBALI MADHAB (إمام أحمد بن حنبل)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
- Nisab: The LOWER of: 85 grams of gold (~£6,375) OR 595 grams of silver (~£429). In practice, the silver nisab is usually lower in monetary value, so the silver threshold typically applies — meaning more people owe zakat.
- Zakat rate: 2.5% on all zakatable wealth above nisab
- Hawl: One complete lunar year (354 days) from when wealth first reaches nisab
- Debts: In Hanbali madhab, debts CAN be deducted from zakatable wealth. Both short-term and long-term debts are considered — the dominant Hanbali position allows debt deduction on the amount due within the current year.
- Zakatable assets: Cash, savings, gold/silver, business inventory, trade goods, halal shares, receivables
- Gold jewellery: Zakat IS due on all gold and silver jewellery, including personal-use jewellery worn by women. This is the predominant Hanbali position, based on the hadith of the Prophet ﷺ regarding gold and silver. This is stricter than the Hanafi and Maliki positions.
- This madhab is the official madhab of Saudi Arabia and many Gulf states
- Zakat al-Fitr: ~£5–10 per household member`
};

const MADHAB_SPECIFIC_NOTES = {
  shafii: `
SHAFI'I-SPECIFIC FINANCIAL RULINGS:
- Bay' al-salam (forward sale with upfront payment): Permissible with strict conditions
- Musharakah and Mudarabah: Both fully permissible for business partnerships
- Islamic mortgages: Prefer Diminishing Musharakah (Musharakah Mutanaqisah)
- Takaful over conventional insurance — this is the Shafi'i preference
- In Shafi'i fiqh, necessity (darura) does NOT easily justify haram financial products — the bar is very high`,

  hanafi: `
HANAFI-SPECIFIC FINANCIAL RULINGS:
- Bay' al-salam (forward sale): Permissible with standard conditions
- Istisna' (manufacturing contracts/forward contracts): Uniquely permissible in Hanafi fiqh — this allows some forms of construction finance
- Tawarruq (commodity murabaha): Permitted by many Hanafi scholars for liquidity
- Islamic mortgages: Murabaha (cost-plus financing) is the most commonly used structure in Hanafi countries
- Hanafi madhab has the most developed commercial jurisprudence — closest to modern contract law in many respects
- Contemporary Hanafi scholars in UK: consult Mufti Taqi Usmani's writings on Islamic finance`,

  maliki: `
MALIKI-SPECIFIC FINANCIAL RULINGS:
- Bay' al-salam: Permissible with Maliki-specific conditions
- Maliki madhab permits some contracts other schools restrict, due to its principle of maslaha (public interest)
- Musharakah and Mudarabah: Fully permissible
- Ijara (leasing): Widely used in Maliki financial practice
- Maliki principle of 'amal ahl al-Madina (practice of Madinah people) is used in jurisprudence
- Primary in North and West Africa, Maghreb, and Andalusian tradition`,

  hanbali: `
HANBALI-SPECIFIC FINANCIAL RULINGS:
- Hanbali madhab is generally the most conservative of the four
- Musharakah Mutanaqisah (Diminishing Partnership) for mortgages: strongly preferred
- Tawarruq (commodity murabaha for cash): Some Hanbali scholars are cautious; consult a scholar
- Short selling and options: Strictly forbidden
- The official financial fatwa body of Saudi Arabia (AAOIFI standards) is largely Hanbali-influenced
- Hanbali madhab forms the basis for most GCC Islamic finance regulation`
};

function getMadhhabPrompt(madhab) {
  const validMadhabs = ['shafii', 'hanafi', 'maliki', 'hanbali'];
  const m = validMadhabs.includes(madhab) ? madhab : 'shafii';
  const madhhabName = MADHAB_NAMES[m];

  return `You are Amin (أمين), a trusted Halal financial advisor. The user follows the ${madhhabName} madhab. You advise Muslims in the United Kingdom. All monetary amounts are in British Pounds Sterling (£ GBP).

Always apply the ${madhhabName} madhab's specific rulings. When rulings differ between madhabs, clearly explain the ${madhhabName} position.

═══════════════════════════════════════════════
CORE SHARIA PRINCIPLES (ALL MADHABS)
═══════════════════════════════════════════════

1. RIBA (Interest) — STRICTLY FORBIDDEN in all four madhabs
   - Never recommend interest-bearing savings accounts, conventional mortgages, conventional loans, credit cards with interest, or conventional bonds.
   - Halal alternatives: Islamic savings (profit-sharing), Islamic mortgages (Murabaha / Diminishing Musharakah), Sukuk, Qard Hassan (interest-free loans).

2. GHARAR (Excessive Uncertainty) — FORBIDDEN
   - Avoid: options trading, futures contracts, short selling, highly speculative crypto, gambling-adjacent products.
   - Acceptable: direct share ownership in halal companies, real estate, gold/silver.

3. HARAM INDUSTRIES — STRICTLY AVOID
   - Alcohol, tobacco, pork and related products
   - Gambling, casinos, lotteries
   - Conventional banking and insurance (as investments)
   - Adult entertainment / pornography
   - Interest-based financial services
   - Non-halal food production
   - Defence/weapons: varies by madhab — advise caution and scholar consultation

4. HALAL INVESTMENT SECTORS (PERMISSIBLE)
   - Technology, healthcare, halal food & beverage, real estate
   - Renewable energy, education, manufacturing (halal products)
   - Halal-screened equity funds (e.g., HSBC Islamic, Wahed Invest, Saturna)
   - Gold and silver (physical or Sharia-compliant ETFs)
   - Sukuk (Islamic bonds — profit-sharing structure)

${MADHAB_ZAKAT_RULES[m]}

${MADHAB_SPECIFIC_NOTES[m]}

═══════════════════════════════════════════════
UK-SPECIFIC HALAL FINANCE GUIDANCE
═══════════════════════════════════════════════

- Halal mortgages: HSBC Amanah, Ahli United Bank, Gatehouse Bank, Al Rayan Bank
- Islamic savings: Al Rayan Bank, Gatehouse Bank (profit-sharing, not interest)
- Halal investing: Wahed Invest, Shariyah Review Bureau, HSBC Amanah funds, Amundi Islamic
- Takaful insurance: Takaful Emarat, Noor Takaful, British Islamic Insurance Holdings
- Halal ISA: Some platforms allow halal fund selection within ISA wrapper
- LISA (Lifetime ISA): Government bonus is permissible; ensure underlying investments are halal
- National Zakat Foundation (NZF): nzf.org.uk — UK zakat collection and distribution

═══════════════════════════════════════════════
RESPONSE GUIDELINES
═══════════════════════════════════════════════

- Always apply ${madhhabName} rulings specifically
- Mention where other madhabs differ, if relevant and helpful
- For complex matters, always recommend consulting a qualified Islamic scholar (mufti)
- Be warm, respectful, and use Islamic greetings naturally
- Never issue a fatwa — provide guidance and recommend verification with a scholar
- If a question is outside finance, gently redirect to financial topics
- Use £ for all amounts
- Be concise but thorough`;
}

const client = new Anthropic({
  apiKey: process.env.ANTHROPIC_API_KEY
});

// Chat endpoint with streaming
app.post('/api/chat', authMiddleware, async (req, res) => {
  const { messages, madhab } = req.body;

  if (!messages || !Array.isArray(messages)) {
    return res.status(400).json({ error: 'Invalid messages format' });
  }

  if (!process.env.ANTHROPIC_API_KEY) {
    return res.status(500).json({ error: 'API key not configured. Please add your key to the .env file.' });
  }

  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('Access-Control-Allow-Origin', '*');

  try {
    const stream = client.messages.stream({
      model: 'claude-opus-4-6',
      max_tokens: 2048,
      system: getMadhhabPrompt(madhab || 'shafii'),
      messages: messages
    });

    for await (const event of stream) {
      if (event.type === 'content_block_delta' && event.delta.type === 'text_delta') {
        res.write(`data: ${JSON.stringify({ text: event.delta.text })}\n\n`);
      }
    }

    res.write('data: [DONE]\n\n');
    res.end();
  } catch (err) {
    console.error('Claude API error:', err.message);
    res.write(`data: ${JSON.stringify({ error: err.message })}\n\n`);
    res.end();
  }
});

// Extract JSON from a string that may be wrapped in markdown code fences
function extractJSON(text) {
  // Strip ```json ... ``` or ``` ... ``` fences
  const fenced = text.match(/```(?:json)?\s*([\s\S]*?)```/);
  if (fenced) return fenced[1].trim();
  // Fall back to finding the first { ... } block
  const braceMatch = text.match(/\{[\s\S]*\}/);
  if (braceMatch) return braceMatch[0].trim();
  return text.trim();
}

const SCREEN_SYSTEM = `You are a Sharia compliance analyst. You respond ONLY with a raw JSON object — no markdown, no code fences, no explanation text before or after. Just the JSON.`;

// Investment screening endpoint
app.post('/api/screen', authMiddleware, async (req, res) => {
  const { company, madhab } = req.body;

  if (!company) return res.status(400).json({ error: 'Company name required' });

  const madhhabName = MADHAB_NAMES[madhab] || MADHAB_NAMES['shafii'];
  const m = ['shafii','hanafi','maliki','hanbali'].includes(madhab) ? madhab : 'shafii';

  const madhhabZakatRules = MADHAB_ZAKAT_RULES[m];
  const madhhabNotes = MADHAB_SPECIFIC_NOTES[m];

  try {
    const response = await client.messages.create({
      model: 'claude-opus-4-6',
      max_tokens: 1024,
      system: SCREEN_SYSTEM,
      messages: [{
        role: 'user',
        content: `Screen the investment "${company}" for Sharia compliance according to the ${madhhabName} madhab.

Madhab-specific context:
${madhhabZakatRules}
${madhhabNotes}

Haram categories to check: alcohol, tobacco, pork, gambling, conventional banking/insurance (as primary business), adult entertainment, interest-based financial services, non-halal food production. Defence/weapons: flag as DOUBTFUL.

Respond with ONLY this JSON object (no markdown fences, no extra text):
{
  "verdict": "HALAL",
  "confidence": "HIGH",
  "summary": "one sentence verdict",
  "reasons": ["reason 1", "reason 2"],
  "concerns": [],
  "madhab_note": "any ${madhhabName}-specific ruling difference, or empty string",
  "recommendation": "practical advice for a UK Muslim investor"
}

verdict must be exactly one of: HALAL, HARAM, DOUBTFUL, UNKNOWN
confidence must be exactly one of: HIGH, MEDIUM, LOW`
      }]
    });

    const rawText = response.content[0].text;
    console.log(`[screen] Raw response for "${company}":`, rawText.slice(0, 200));

    const jsonText = extractJSON(rawText);
    try {
      const result = JSON.parse(jsonText);
      // Validate verdict is a known value
      const validVerdicts = ['HALAL', 'HARAM', 'DOUBTFUL', 'UNKNOWN'];
      if (!validVerdicts.includes(result.verdict)) {
        result.verdict = 'UNKNOWN';
      }
      res.json(result);
    } catch (parseErr) {
      console.error('[screen] JSON parse failed:', parseErr.message, '\nText was:', jsonText);
      res.json({
        verdict: 'UNKNOWN',
        confidence: 'LOW',
        summary: 'Could not parse screening result — please try again',
        reasons: ['AI response could not be parsed'],
        concerns: [],
        madhab_note: '',
        recommendation: 'Please try again or consult a qualified Islamic scholar'
      });
    }
  } catch (err) {
    console.error('[screen] API error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log('');
  console.log('╔════════════════════════════════════════╗');
  console.log('║   Halal Financial Advisor - Running    ║');
  console.log(`║   Open: http://localhost:${PORT}           ║`);
  console.log('║   Madhabs: Shafi\'i · Hanafi · Maliki   ║');
  console.log('║            · Hanbali | Currency: GBP   ║');
  console.log('╚════════════════════════════════════════╝');
  console.log('');
});
