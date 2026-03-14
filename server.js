require('dotenv').config();
const express = require('express');
const path = require('path');
const Anthropic = require('@anthropic-ai/sdk');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Stripe = require('stripe');
const { Resend } = require('resend');
const crypto = require('crypto');

// ─────────────────────────────────────────────
// DATABASE (PostgreSQL)
// ─────────────────────────────────────────────

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id                   SERIAL PRIMARY KEY,
      email                TEXT UNIQUE NOT NULL,
      password_hash        TEXT NOT NULL,
      trial_start          BIGINT NOT NULL,
      created_at           BIGINT NOT NULL,
      subscription_status  TEXT DEFAULT 'trialing',
      stripe_customer_id   TEXT,
      stripe_subscription_id TEXT
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS user_data (
      user_id    INTEGER NOT NULL REFERENCES users(id),
      data_key   TEXT NOT NULL,
      data_value TEXT NOT NULL,
      updated_at BIGINT NOT NULL,
      PRIMARY KEY (user_id, data_key)
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS password_reset_tokens (
      id         SERIAL PRIMARY KEY,
      user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      token      TEXT NOT NULL UNIQUE,
      expires_at BIGINT NOT NULL,
      used       BOOLEAN DEFAULT FALSE
    )
  `);
}

// ─────────────────────────────────────────────
// STRIPE & AUTH SETUP
// ─────────────────────────────────────────────

const stripe = process.env.STRIPE_SECRET_KEY
  ? new Stripe(process.env.STRIPE_SECRET_KEY, { apiVersion: '2023-10-16' })
  : null;

const resend = process.env.RESEND_API_KEY ? new Resend(process.env.RESEND_API_KEY) : null;

async function sendPasswordResetEmail(toEmail, resetUrl) {
  if (!resend) {
    console.warn('[email] RESEND_API_KEY not set — password reset email not sent. Reset URL:', resetUrl);
    return;
  }
  await resend.emails.send({
    from: 'Halal Advisor <onboarding@resend.dev>',
    to: toEmail,
    subject: 'Reset your Halal Advisor password',
    html: `
      <div style="font-family:sans-serif;max-width:480px;margin:0 auto;padding:32px 24px;">
        <h2 style="color:#1a5c38;font-size:1.4rem;margin-bottom:8px;">☽ Halal Advisor</h2>
        <p style="color:#333;font-size:0.95rem;line-height:1.6;">
          We received a request to reset the password for your account (<strong>${toEmail}</strong>).
        </p>
        <p style="color:#333;font-size:0.95rem;line-height:1.6;">
          Click the button below to choose a new password. This link expires in <strong>1 hour</strong>.
        </p>
        <a href="${resetUrl}" style="display:inline-block;margin:20px 0;padding:12px 28px;background:#1a5c38;color:#fff;text-decoration:none;border-radius:8px;font-weight:600;font-size:0.95rem;">
          Reset Password
        </a>
        <p style="color:#718096;font-size:0.8rem;margin-top:24px;">
          If you did not request a password reset, you can safely ignore this email — your password will not change.
        </p>
        <hr style="border:none;border-top:1px solid #e2e8f0;margin:24px 0;" />
        <p style="color:#a0aec0;font-size:0.75rem;">Halal Advisor · Islamic Financial Guidance</p>
      </div>
    `
  });
}

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

const app = express();

// ── Stripe webhook must receive raw body — register BEFORE express.json() ──
app.post('/api/stripe/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.headers['stripe-signature'];
  if (!process.env.STRIPE_WEBHOOK_SECRET) {
    console.error('[webhook] STRIPE_WEBHOOK_SECRET not set');
    return res.status(500).send('Webhook secret not configured');
  }
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error('[webhook] Signature verification failed:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  try {
    switch (event.type) {
      case 'checkout.session.completed': {
        const session = event.data.object;
        if (session.mode === 'subscription') {
          await pool.query(
            'UPDATE users SET subscription_status = $1, stripe_subscription_id = $2 WHERE stripe_customer_id = $3',
            ['active', session.subscription, session.customer]
          );
          console.log('[webhook] Subscription activated for customer', session.customer);
        }
        break;
      }
      case 'customer.subscription.updated': {
        const sub = event.data.object;
        const status = sub.status === 'active' ? 'active' : sub.status;
        await pool.query(
          'UPDATE users SET subscription_status = $1 WHERE stripe_customer_id = $2',
          [status, sub.customer]
        );
        console.log('[webhook] Subscription updated:', status, 'for', sub.customer);
        break;
      }
      case 'customer.subscription.deleted': {
        const sub = event.data.object;
        await pool.query(
          'UPDATE users SET subscription_status = $1 WHERE stripe_customer_id = $2',
          ['cancelled', sub.customer]
        );
        console.log('[webhook] Subscription cancelled for', sub.customer);
        break;
      }
      case 'invoice.payment_failed': {
        const invoice = event.data.object;
        await pool.query(
          'UPDATE users SET subscription_status = $1 WHERE stripe_customer_id = $2',
          ['past_due', invoice.customer]
        );
        console.log('[webhook] Payment failed for', invoice.customer);
        break;
      }
    }
  } catch (err) {
    console.error('[webhook] DB error:', err.message);
  }

  res.json({ received: true });
});

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ─────────────────────────────────────────────
// AUTH ROUTES
// ─────────────────────────────────────────────

// POST /api/auth/signup
app.post('/api/auth/signup', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required.' });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: 'Invalid email address.' });
  if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  try {
    const hash = await bcrypt.hash(password, 12);
    const now = Date.now();
    const result = await pool.query(
      'INSERT INTO users (email, password_hash, trial_start, created_at) VALUES ($1, $2, $3, $4) RETURNING id',
      [email.toLowerCase(), hash, now, now]
    );
    const token = jwt.sign({ userId: result.rows[0].id, email: email.toLowerCase() }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, email: email.toLowerCase(), trialDaysLeft: TRIAL_DAYS, subscriptionStatus: 'trialing' });
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'This email is already registered. Please sign in.' });
    console.error('[signup]', err.message);
    res.status(500).json({ error: 'Registration failed. Please try again.' });
  }
});

// POST /api/auth/login
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required.' });
  try {
    const { rows } = await pool.query('SELECT * FROM users WHERE email = $1', [email.toLowerCase()]);
    const user = rows[0];
    if (!user) return res.status(401).json({ error: 'Invalid email or password.' });
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: 'Invalid email or password.' });
    const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
    const days = trialDaysLeft(Number(user.trial_start));
    res.json({
      token,
      email: user.email,
      trialDaysLeft: days,
      subscriptionStatus: user.subscription_status || 'trialing'
    });
  } catch (err) {
    console.error('[login]', err.message);
    res.status(500).json({ error: 'Login failed. Please try again.' });
  }
});

// POST /api/auth/forgot-password
app.post('/api/auth/forgot-password', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email required.' });
  // Always respond OK so we don't reveal whether the email exists
  res.json({ ok: true });
  try {
    const { rows } = await pool.query('SELECT id FROM users WHERE email = $1', [email.toLowerCase()]);
    if (!rows.length) return; // No account — silently do nothing
    const userId = rows[0].id;
    // Delete any existing unexpired tokens for this user
    await pool.query('DELETE FROM password_reset_tokens WHERE user_id = $1', [userId]);
    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = Date.now() + 60 * 60 * 1000; // 1 hour
    await pool.query(
      'INSERT INTO password_reset_tokens (user_id, token, expires_at) VALUES ($1, $2, $3)',
      [userId, token, expiresAt]
    );
    const appUrl = process.env.APP_URL || 'http://localhost:3000';
    const resetUrl = `${appUrl}/?resetToken=${token}`;
    await sendPasswordResetEmail(email.toLowerCase(), resetUrl);
    console.log('[forgot-password] Reset link sent to', email.toLowerCase());
  } catch (err) {
    console.error('[forgot-password]', err.message);
  }
});

// POST /api/auth/reset-password
app.post('/api/auth/reset-password', async (req, res) => {
  const { token, password } = req.body;
  if (!token || !password) return res.status(400).json({ error: 'Token and new password required.' });
  if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  try {
    const { rows } = await pool.query(
      'SELECT * FROM password_reset_tokens WHERE token = $1 AND used = FALSE',
      [token]
    );
    if (!rows.length) return res.status(400).json({ error: 'Invalid or expired reset link.' });
    const record = rows[0];
    if (Date.now() > Number(record.expires_at)) {
      await pool.query('DELETE FROM password_reset_tokens WHERE id = $1', [record.id]);
      return res.status(400).json({ error: 'This reset link has expired. Please request a new one.' });
    }
    const hash = await bcrypt.hash(password, 12);
    await pool.query('UPDATE users SET password_hash = $1 WHERE id = $2', [hash, record.user_id]);
    await pool.query('UPDATE password_reset_tokens SET used = TRUE WHERE id = $1', [record.id]);
    console.log('[reset-password] Password reset for user', record.user_id);
    res.json({ ok: true });
  } catch (err) {
    console.error('[reset-password]', err.message);
    res.status(500).json({ error: 'Password reset failed. Please try again.' });
  }
});

// GET /api/user/me
app.get('/api/user/me', authMiddleware, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM users WHERE id = $1', [req.user.userId]);
    const user = rows[0];
    if (!user) return res.status(404).json({ error: 'User not found.' });
    const days = trialDaysLeft(Number(user.trial_start));
    const subscriptionStatus = user.subscription_status || 'trialing';
    const hasAccess = days > 0 || subscriptionStatus === 'active';
    res.json({ email: user.email, trialDaysLeft: days, subscriptionStatus, hasAccess });
  } catch (err) {
    console.error('[me]', err.message);
    res.status(500).json({ error: 'Server error.' });
  }
});

// GET /api/user/data
app.get('/api/user/data', authMiddleware, async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT data_key, data_value FROM user_data WHERE user_id = $1',
      [req.user.userId]
    );
    const result = {};
    for (const row of rows) {
      try { result[row.data_key] = JSON.parse(row.data_value); } catch { result[row.data_key] = row.data_value; }
    }
    res.json(result);
  } catch (err) {
    console.error('[user/data GET]', err.message);
    res.status(500).json({ error: 'Server error.' });
  }
});

// PUT /api/user/data
app.put('/api/user/data', authMiddleware, async (req, res) => {
  const { key, value } = req.body;
  if (!key) return res.status(400).json({ error: 'Data key required.' });
  try {
    await pool.query(
      `INSERT INTO user_data (user_id, data_key, data_value, updated_at)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (user_id, data_key)
       DO UPDATE SET data_value = EXCLUDED.data_value, updated_at = EXCLUDED.updated_at`,
      [req.user.userId, key, JSON.stringify(value), Date.now()]
    );
    res.json({ ok: true });
  } catch (err) {
    console.error('[user/data PUT]', err.message);
    res.status(500).json({ error: 'Server error.' });
  }
});

// ─────────────────────────────────────────────
// STRIPE PAYMENTS
// ─────────────────────────────────────────────

// POST /api/stripe/create-checkout-session
app.post('/api/stripe/create-checkout-session', authMiddleware, async (req, res) => {
  if (!stripe) return res.status(500).json({ error: 'Stripe is not configured. Add STRIPE_SECRET_KEY to your environment.' });
  if (!process.env.STRIPE_PRICE_ID) return res.status(500).json({ error: 'STRIPE_PRICE_ID not configured.' });
  try {
    const { rows } = await pool.query('SELECT * FROM users WHERE id = $1', [req.user.userId]);
    const user = rows[0];
    const appUrl = process.env.APP_URL || 'http://localhost:3000';
    let customerId = user.stripe_customer_id;
    if (!customerId) {
      const customer = await stripe.customers.create({ email: user.email });
      customerId = customer.id;
      await pool.query('UPDATE users SET stripe_customer_id = $1 WHERE id = $2', [customerId, user.id]);
    }
    const session = await stripe.checkout.sessions.create({
      customer: customerId,
      payment_method_types: ['card'],
      line_items: [{ price: process.env.STRIPE_PRICE_ID, quantity: 1 }],
      mode: 'subscription',
      success_url: `${appUrl}/?subscribed=1`,
      cancel_url: `${appUrl}/`,
      allow_promotion_codes: true,
      subscription_data: { metadata: { userId: String(user.id) } }
    });
    res.json({ url: session.url });
  } catch (err) {
    console.error('[stripe] Checkout session error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// POST /api/stripe/portal
app.post('/api/stripe/portal', authMiddleware, async (req, res) => {
  if (!stripe) return res.status(500).json({ error: 'Stripe is not configured.' });
  try {
    const { rows } = await pool.query('SELECT * FROM users WHERE id = $1', [req.user.userId]);
    const user = rows[0];
    if (!user.stripe_customer_id) return res.status(400).json({ error: 'No subscription found for this account.' });
    const session = await stripe.billingPortal.sessions.create({
      customer: user.stripe_customer_id,
      return_url: process.env.APP_URL || 'http://localhost:3000'
    });
    res.json({ url: session.url });
  } catch (err) {
    console.error('[stripe] Portal error:', err.message);
    res.status(500).json({ error: err.message });
  }
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

const LANG_INSTRUCTIONS = {
  en: '',
  ar: 'IMPORTANT: You MUST respond entirely in Arabic (العربية). Use formal Modern Standard Arabic.',
  ur: 'IMPORTANT: You MUST respond entirely in Urdu (اردو). Use formal Urdu script.',
  bn: 'IMPORTANT: You MUST respond entirely in Bengali (বাংলা). Use standard Bengali.',
  tr: 'IMPORTANT: You MUST respond entirely in Turkish (Türkçe). Use formal Turkish.',
  fr: 'IMPORTANT: You MUST respond entirely in French (Français). Use formal French.',
  es: 'IMPORTANT: You MUST respond entirely in Spanish (Español). Use formal Spanish.',
  pt: 'IMPORTANT: You MUST respond entirely in Portuguese (Português). Use formal Portuguese.',
  de: 'IMPORTANT: You MUST respond entirely in German (Deutsch). Use formal German.',
  id: 'IMPORTANT: You MUST respond entirely in Indonesian (Bahasa Indonesia). Use formal Indonesian.',
  ms: 'IMPORTANT: You MUST respond entirely in Malay (Bahasa Melayu). Use formal Malaysian Malay.',
  fa: 'IMPORTANT: You MUST respond entirely in Persian/Farsi (فارسی). Use formal Modern Persian.',
  ha: 'IMPORTANT: You MUST respond entirely in Hausa. Use formal Hausa.',
  sw: 'IMPORTANT: You MUST respond entirely in Swahili (Kiswahili). Use formal Swahili.',
  so: 'IMPORTANT: You MUST respond entirely in Somali (Soomaali). Use formal Somali.'
};

function getMadhhabPrompt(madhab, lang) {
  const validMadhabs = ['shafii', 'hanafi', 'maliki', 'hanbali'];
  const m = validMadhabs.includes(madhab) ? madhab : 'shafii';
  const madhhabName = MADHAB_NAMES[m];
  const langInstruction = LANG_INSTRUCTIONS[lang] || '';

  return `You are Amin (أمين), a trusted Halal financial advisor. The user follows the ${madhhabName} madhab. You advise Muslims in the United Kingdom. All monetary amounts are in British Pounds Sterling (£ GBP).
${langInstruction ? '\n' + langInstruction + '\n' : ''}

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
- Be concise but thorough
${langInstruction ? '- ' + langInstruction : ''}`;
}

const client = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

// Chat endpoint with streaming
app.post('/api/chat', authMiddleware, async (req, res) => {
  const { messages, madhab, lang } = req.body;
  if (!messages || !Array.isArray(messages)) return res.status(400).json({ error: 'Invalid messages format' });
  if (!process.env.ANTHROPIC_API_KEY) return res.status(500).json({ error: 'API key not configured.' });

  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('Access-Control-Allow-Origin', '*');

  try {
    const stream = client.messages.stream({
      model: 'claude-opus-4-6',
      max_tokens: 2048,
      system: getMadhhabPrompt(madhab || 'shafii', lang || 'en'),
      messages
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
  const fenced = text.match(/```(?:json)?\s*([\s\S]*?)```/);
  if (fenced) return fenced[1].trim();
  const braceMatch = text.match(/\{[\s\S]*\}/);
  if (braceMatch) return braceMatch[0].trim();
  return text.trim();
}

const SCREEN_SYSTEM = `You are a Sharia compliance analyst. You respond ONLY with a raw JSON object — no markdown, no code fences, no explanation text before or after. Just the JSON.`;

// Investment screening endpoint
app.post('/api/screen', authMiddleware, async (req, res) => {
  const { company, madhab, lang } = req.body;
  if (!company) return res.status(400).json({ error: 'Company name required' });

  const madhhabName = MADHAB_NAMES[madhab] || MADHAB_NAMES['shafii'];
  const m = ['shafii','hanafi','maliki','hanbali'].includes(madhab) ? madhab : 'shafii';
  const langNote = LANG_INSTRUCTIONS[lang] ? `\n${LANG_INSTRUCTIONS[lang]}` : '';

  try {
    const response = await client.messages.create({
      model: 'claude-opus-4-6',
      max_tokens: 1024,
      system: SCREEN_SYSTEM,
      messages: [{
        role: 'user',
        content: `Screen the investment "${company}" for Sharia compliance according to the ${madhhabName} madhab.

Madhab-specific context:
${MADHAB_ZAKAT_RULES[m]}
${MADHAB_SPECIFIC_NOTES[m]}

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
confidence must be exactly one of: HIGH, MEDIUM, LOW
${langNote}`
      }]
    });

    const rawText = response.content[0].text;
    console.log(`[screen] Raw response for "${company}":`, rawText.slice(0, 200));

    const jsonText = extractJSON(rawText);
    try {
      const result = JSON.parse(jsonText);
      const validVerdicts = ['HALAL', 'HARAM', 'DOUBTFUL', 'UNKNOWN'];
      if (!validVerdicts.includes(result.verdict)) result.verdict = 'UNKNOWN';
      res.json(result);
    } catch (parseErr) {
      console.error('[screen] JSON parse failed:', parseErr.message);
      res.json({ verdict: 'UNKNOWN', confidence: 'LOW', summary: 'Could not parse screening result — please try again', reasons: ['AI response could not be parsed'], concerns: [], madhab_note: '', recommendation: 'Please try again or consult a qualified Islamic scholar' });
    }
  } catch (err) {
    console.error('[screen] API error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ─────────────────────────────────────────────
// START SERVER
// ─────────────────────────────────────────────

const PORT = process.env.PORT || 3000;
initDb()
  .then(() => {
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
  })
  .catch(err => {
    console.error('❌ Database connection failed:', err.message);
    process.exit(1);
  });
