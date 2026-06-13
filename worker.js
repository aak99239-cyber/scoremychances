// ─────────────────────────────────────────────────────────────
//  ScoreMyChances — Cloudflare Worker (secured)
//
//  Environment variables to set in Cloudflare dashboard:
//    GROQ_API_KEY      → your free Groq API key (console.groq.com)
//    SITE_TOKEN        → any long random secret, must match HTML file
//    RESEND_API_KEY    → your free Resend API key (resend.com)
//                        Used to send welcome emails automatically
//    TURNSTILE_SECRET  → Cloudflare Turnstile SECRET key (dash.cloudflare.com → Turnstile)
//                        Leave unset during dev — CAPTCHA is skipped if not configured
//    LEMON_SQUEEZY_WEBHOOK_SECRET → LS webhook signing secret (required for any Pro/trial grants)
//    LS_API_KEY        → Lemon Squeezy API key (Settings → API). Used to cancel
//                        subscriptions server-side when a user cancels a trial/plan.
//
//  KV Namespace bindings (optional but recommended — both are free):
//    AUTH_KV      → KV namespace "AUTH_DB"      bound as: AUTH_KV
//    COMMUNITY_DB → KV namespace "COMMUNITY_DB" bound as: COMMUNITY_DB
//
//  Rate limit: 15 requests per IP per minute (free, no KV needed)
// ─────────────────────────────────────────────────────────────

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, X-Site-Token',
};

// Hard limits — reject anything bigger than this
const MAX_BODY_BYTES   = 32_000;   // 32 KB max request body
const MAX_MSG_CHARS    = 12_000;   // max userMessage length
const MAX_PROMPT_CHARS = 4_000;    // max systemPrompt length
const RATE_LIMIT_MAX   = 15;       // max requests per window
const RATE_LIMIT_SECS  = 60;       // window size in seconds

// ── Simple IP rate limiter using Cloudflare Cache API ─────────
async function checkRateLimit(ip) {
  const cacheKey = new Request(`https://rate-limit-cache/${ip}`);
  const cache = caches.default;

  const cached = await cache.match(cacheKey);
  let count = 1;

  if (cached) {
    const data = await cached.json();
    count = (data.count || 0) + 1;
  }

  if (count > RATE_LIMIT_MAX) return false; // blocked

  // Store updated count with TTL
  const res = new Response(JSON.stringify({ count }), {
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': `public, max-age=${RATE_LIMIT_SECS}`,
    },
  });
  await cache.put(cacheKey, res);
  return true; // allowed
}

// ── Input sanitiser — strips control characters, limits length ─
function sanitize(str, maxLen) {
  if (typeof str !== 'string') return '';
  // Remove null bytes and non-printable control chars (keep \n \t)
  return str.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '').slice(0, maxLen);
}

// ── Password hashing (PBKDF2 / Web Crypto) ────────────────────
async function hashPassword(password, salt) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: enc.encode(salt), iterations: 100000, hash: 'SHA-256' },
    key, 256
  );
  return btoa(String.fromCharCode(...new Uint8Array(bits)));
}

function makeSalt() {
  const arr = new Uint8Array(16);
  crypto.getRandomValues(arr);
  return Array.from(arr).map(b => b.toString(16).padStart(2,'0')).join('');
}

function makeToken() {
  const arr = new Uint8Array(32);
  crypto.getRandomValues(arr);
  return Array.from(arr).map(b => b.toString(16).padStart(2,'0')).join('');
}

// ── Email sending via Resend ──────────────────────────────────
async function sendEmail(env, { to, subject, html }) {
  if (!env.RESEND_API_KEY) return; // silently skip if not configured
  try {
    await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${env.RESEND_API_KEY}`,
      },
      body: JSON.stringify({
        from: 'ScoreMyChances <onboarding@resend.dev>',
        to: [to],
        subject,
        html,
      }),
    });
  } catch(e) {} // never let email failure break the signup flow
}

function welcomeEmailHtml(name, marketingOk) {
  return `<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#080a12;font-family:'Helvetica Neue',Arial,sans-serif">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#080a12;padding:40px 0">
    <tr><td align="center">
      <table width="560" cellpadding="0" cellspacing="0" style="background:#0f1120;border-radius:20px;border:1px solid rgba(255,255,255,.08);overflow:hidden;max-width:560px;width:100%">

        <!-- Header -->
        <tr><td style="background:linear-gradient(135deg,#6366f1,#8b5cf6,#a855f7);padding:36px 40px;text-align:center">
          <div style="display:inline-flex;align-items:center;gap:10px">
            <div style="background:rgba(255,255,255,.2);border-radius:12px;width:42px;height:42px;display:inline-flex;align-items:center;justify-content:center;font-size:16px;font-weight:900;color:white">SM</div>
            <span style="font-size:20px;font-weight:900;color:white">ScoreMyChances</span>
          </div>
          <div style="font-size:28px;margin-top:20px">👋</div>
          <h1 style="color:white;font-size:26px;font-weight:900;margin:10px 0 6px;letter-spacing:-1px">Hey, ${sanitize(name, 50)}!</h1>
          <p style="color:rgba(255,255,255,.75);font-size:15px;margin:0">Welcome to ScoreMyChances</p>
        </td></tr>

        <!-- Body -->
        <tr><td style="padding:36px 40px">
          <p style="color:rgba(255,255,255,.75);font-size:15px;line-height:1.7;margin:0 0 20px">
            Your account is all set up and ready to go. Here's what you can do right now:
          </p>

          <!-- Features -->
          <table width="100%" cellpadding="0" cellspacing="0">
            <tr><td style="padding:12px 16px;background:rgba(99,102,241,.1);border:1px solid rgba(99,102,241,.2);border-radius:12px;margin-bottom:10px">
              <span style="font-size:20px">🎓</span>
              <span style="color:white;font-weight:700;font-size:14px;margin-left:10px">University Predictor</span>
              <p style="color:rgba(255,255,255,.5);font-size:13px;margin:4px 0 0 30px;line-height:1.5">Enter your profile and get an AI prediction of your chances at any university in the world.</p>
            </td></tr>
          </table>
          <div style="height:8px"></div>
          <table width="100%" cellpadding="0" cellspacing="0">
            <tr><td style="padding:12px 16px;background:rgba(99,102,241,.1);border:1px solid rgba(99,102,241,.2);border-radius:12px">
              <span style="font-size:20px">💼</span>
              <span style="color:white;font-weight:700;font-size:14px;margin-left:10px">Job & Career Predictor</span>
              <p style="color:rgba(255,255,255,.5);font-size:13px;margin:4px 0 0 30px;line-height:1.5">See how you stack up for any role at any company — with specific tips to improve your chances.</p>
            </td></tr>
          </table>

          <div style="height:28px"></div>

          <!-- Pro teaser -->
          <table width="100%" cellpadding="0" cellspacing="0">
            <tr><td style="background:linear-gradient(135deg,rgba(168,85,247,.15),rgba(99,102,241,.1));border:1px solid rgba(168,85,247,.3);border-radius:14px;padding:20px 24px;text-align:center">
              <div style="font-size:24px">👑</div>
              <p style="color:white;font-weight:800;font-size:15px;margin:8px 0 6px">Try ScoreMyChances Pro</p>
              <p style="color:rgba(255,255,255,.5);font-size:13px;margin:0 0 14px;line-height:1.6">Essay Workshop, Multi-School Compare, Progress Tracker, Interview Simulator & more — starting at $7.99/month.</p>
              <a href="https://scoremychances.com" style="display:inline-block;background:linear-gradient(135deg,#6366f1,#8b5cf6);color:white;font-weight:700;font-size:14px;padding:12px 28px;border-radius:10px;text-decoration:none">See Pro Features →</a>
            </td></tr>
          </table>

          <div style="height:28px"></div>
          <p style="color:rgba(255,255,255,.35);font-size:13px;line-height:1.7;margin:0">
            Got questions? Just reply to this email — we read every message.<br>
            Good luck with your applications! 🚀
          </p>
        </td></tr>

        <!-- Footer -->
        <tr><td style="padding:20px 40px;border-top:1px solid rgba(255,255,255,.06);text-align:center">
          <p style="color:rgba(255,255,255,.2);font-size:11px;margin:0;line-height:1.6">
            © ${new Date().getFullYear()} ScoreMyChances · <a href="https://scoremychances.com" style="color:rgba(255,255,255,.3)">scoremychances.com</a><br>
            You received this email because you created a ScoreMyChances account. This is a transactional email related to your account.${marketingOk ? '<br>You also opted in to product updates. You can unsubscribe at any time by visiting your account settings.' : ''}
          </p>
        </td></tr>

      </table>
    </td></tr>
  </table>
</body>
</html>`;
}

// ── Free trial confirmation email ─────────────────────────────
// Doubles as the advance notice of the upcoming automatic charge,
// required disclosure for auto-renewing free trials in many jurisdictions.
function trialStartedEmailHtml(name, trialEndsAtMs) {
  const endDate = new Date(trialEndsAtMs);
  const formatted = endDate.toUTCString().replace(' GMT', ' UTC');
  return `<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#080a12;font-family:'Helvetica Neue',Arial,sans-serif">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#080a12;padding:40px 0">
    <tr><td align="center">
      <table width="560" cellpadding="0" cellspacing="0" style="background:#0f1120;border-radius:20px;border:1px solid rgba(255,255,255,.08);overflow:hidden;max-width:560px;width:100%">
        <tr><td style="background:linear-gradient(135deg,#22c55e,#16a34a);padding:32px 40px;text-align:center">
          <div style="font-size:28px">🎁</div>
          <h1 style="color:white;font-size:24px;font-weight:900;margin:10px 0 4px">Your 24-hour Pro trial has started</h1>
          <p style="color:rgba(255,255,255,.85);font-size:14px;margin:0">Hey ${sanitize(name, 50)}, all Pro features are unlocked right now.</p>
        </td></tr>
        <tr><td style="padding:32px 40px">
          <p style="color:rgba(255,255,255,.8);font-size:14px;line-height:1.7;margin:0 0 14px">
            <strong>Important:</strong> unless you cancel before then, your trial will end and you'll be automatically charged <strong>$4.99</strong> for the Monthly Pro plan on:
          </p>
          <p style="background:rgba(99,102,241,.12);border:1px solid rgba(99,102,241,.3);border-radius:10px;padding:14px 18px;color:white;font-weight:700;font-size:15px;text-align:center;margin:0 0 18px">${formatted}</p>
          <p style="color:rgba(255,255,255,.6);font-size:13px;line-height:1.7;margin:0">
            To cancel and avoid any charge, sign in and go to <strong>"Manage plan" → "Cancel Subscription"</strong> any time before the date above — it takes effect immediately and you won't be billed.
          </p>
        </td></tr>
        <tr><td style="padding:20px 40px;border-top:1px solid rgba(255,255,255,.06);text-align:center">
          <p style="color:rgba(255,255,255,.2);font-size:11px;margin:0;line-height:1.6">
            © ${new Date().getFullYear()} ScoreMyChances · Questions? Reply to this email or contact <a href="mailto:support@scoremychances.com" style="color:rgba(255,255,255,.3)">support@scoremychances.com</a>
          </p>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>`;
}

// ── Auth helpers (require AUTH_KV binding in Cloudflare) ──────
async function authSignup(env, body, request) {
  if (!env.AUTH_KV) return { error: 'Auth not configured (AUTH_KV not bound).' };
  // Verify Cloudflare Turnstile CAPTCHA (if secret configured)
  if (env.TURNSTILE_SECRET) {
    const captchaToken = String(body.captchaToken || '');
    if (!captchaToken) return { error: 'CAPTCHA token missing. Please complete the CAPTCHA.' };
    try {
      const verifyRes = await fetch('https://challenges.cloudflare.com/turnstile/v1/siteverify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          secret: env.TURNSTILE_SECRET,
          response: captchaToken,
          remoteip: request.headers.get('CF-Connecting-IP') || ''
        })
      });
      const verifyData = await verifyRes.json();
      if (!verifyData.success) return { error: 'CAPTCHA verification failed. Please try again.' };
    } catch(e) {
      return { error: 'CAPTCHA check failed. Please try again.' };
    }
  }
  const name     = sanitize(String(body.name     || ''), 50).trim();
  const email    = sanitize(String(body.email    || ''), 200).toLowerCase().trim();
  const password = String(body.password || '');
  if (!name || !email || password.length < 8) return { error: 'Invalid signup data.' };
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return { error: 'Invalid email address.' };
  const existing = await env.AUTH_KV.get('user:' + email);
  if (existing) return { error: 'An account with this email already exists.' };
  const salt         = makeSalt();
  const passwordHash = await hashPassword(password, salt);
  const marketingOk  = body.marketingOk === true || body.marketingOk === 'true';
  const user = { name, email, salt, passwordHash, marketingOk, createdAt: Date.now() };
  await env.AUTH_KV.put('user:' + email, JSON.stringify(user));
  // Increment user counter (non-blocking)
  env.AUTH_KV.get('total_users').then(function(v){ env.AUTH_KV.put('total_users', String(parseInt(v||'0')+1)); }).catch(function(){});
  const token = makeToken();
  await env.AUTH_KV.put('session:' + token, JSON.stringify({ email, expiresAt: Date.now() + 30*24*60*60*1000 }), { expirationTtl: 30*24*60*60 });

  // Send welcome email (non-blocking — don't await so it doesn't slow signup)
  sendEmail(env, {
    to: email,
    subject: `Hey ${name}, welcome to ScoreMyChances! 🎉`,
    html: welcomeEmailHtml(name, marketingOk),
  });

  return { ok: true, name, email, token };
}

// ── Billing period helpers ─────────────────────────────────────
// Monthly plans last exactly 30 days, yearly plans exactly 365 days,
// regardless of calendar month length. Access ends at 23:59:59 UTC on
// the final day.
function endOfDayUTC(ts) {
  const d = new Date(ts);
  d.setUTCHours(23, 59, 59, 999);
  return d.getTime();
}
function planFromPayload(payload) {
  const name = (
    (payload?.data?.attributes?.variant_name || '') + ' ' +
    (payload?.data?.attributes?.product_name || '')
  ).toLowerCase();
  return /year|annual/.test(name) ? 'yearly' : 'monthly';
}
function computeProExpiry(plan, fromTs) {
  const days = plan === 'yearly' ? 365 : 30;
  return endOfDayUTC(fromTs + days * 24 * 60 * 60 * 1000);
}

// ── Lemon Squeezy webhook handler ─────────────────────────────
async function handleLSWebhook(env, request) {
  const rawBody = await request.text();

  // Verify HMAC-SHA256 signature from Lemon Squeezy.
  // Fail CLOSED: without a configured secret, anyone could POST a fake
  // "order_created" event and grant themselves Pro for free.
  if (!env.LEMON_SQUEEZY_WEBHOOK_SECRET) {
    return json({ error: 'Webhook not configured' }, 503);
  }
  const signature = request.headers.get('X-Signature') || '';
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw', enc.encode(env.LEMON_SQUEEZY_WEBHOOK_SECRET),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sigBytes = await crypto.subtle.sign('HMAC', key, enc.encode(rawBody));
  const expectedSig = Array.from(new Uint8Array(sigBytes))
    .map(b => b.toString(16).padStart(2,'0')).join('');
  if (signature !== expectedSig) {
    return json({ error: 'Invalid signature' }, 403);
  }

  let payload;
  try { payload = JSON.parse(rawBody); } catch { return json({ error: 'Invalid JSON' }, 400); }

  const eventName = payload?.meta?.event_name || '';

  // Extract email — check custom_data first (most reliable), then user_email
  const email = (
    payload?.meta?.custom_data?.user_email ||
    payload?.data?.attributes?.user_email  ||
    payload?.data?.attributes?.customer_email || ''
  ).toLowerCase().trim();

  if (!email || !env.AUTH_KV) return json({ ok: true }, 200);
  const userKey = 'user:' + email;

  // Subscription cancelled / expired: stop auto-renewal, but Pro access
  // (whether trial or paid) continues until proExpiresAt — checked on login.
  if (eventName === 'subscription_cancelled' || eventName === 'subscription_expired') {
    const raw = await env.AUTH_KV.get(userKey);
    if (raw) {
      const user = JSON.parse(raw);
      user.proAutoRenew = false;
      await env.AUTH_KV.put(userKey, JSON.stringify(user));
    }
    return json({ ok: true }, 200);
  }

  // Only act on successful payment / trial-start events
  const payEvents = ['order_created','subscription_created','subscription_renewed','subscription_payment_success'];
  if (!payEvents.includes(eventName)) {
    return json({ ok: true, ignored: eventName }, 200);
  }

  // Load user, set pro: true with a billing-period (or trial) expiry, save back
  const raw = await env.AUTH_KV.get(userKey);
  if (raw) {
    const user = JSON.parse(raw);
    const attrs = payload?.data?.attributes || {};
    const isTrial = eventName === 'subscription_created' && attrs.status === 'on_trial' && attrs.trial_ends_at;

    user.pro = true;
    user.proSince = Date.now();
    user.proEvent = eventName;
    user.proAutoRenew = true;
    if (payload?.data?.id) user.lsSubscriptionId = payload.data.id;

    if (isTrial) {
      // One-time 24-hour free trial. trial_ends_at comes straight from
      // Lemon Squeezy, so it's exactly 24h from purchase regardless of
      // local time-of-day.
      user.proPlan = 'trial';
      user.proIsTrial = true;
      user.proTrialUsed = true;
      user.proExpiresAt = new Date(attrs.trial_ends_at).getTime();
      // Advance notice of the upcoming auto-charge — required disclosure
      // for auto-renewing free trials in several jurisdictions.
      sendEmail(env, {
        to: email,
        subject: `Your free trial has started — charge scheduled for ${new Date(user.proExpiresAt).toUTCString().replace(' GMT',' UTC')}`,
        html: trialStartedEmailHtml(user.name, user.proExpiresAt),
      });
    } else {
      const plan = planFromPayload(payload);
      user.proPlan = plan;
      user.proIsTrial = false;
      // Renewals extend from the current expiry if it's still in the future,
      // otherwise (new subscription, trial converting, or lapsed) start fresh from now.
      const base = (user.proExpiresAt && user.proExpiresAt > Date.now()) ? user.proExpiresAt : Date.now();
      user.proExpiresAt = computeProExpiry(plan, base);
    }
    await env.AUTH_KV.put(userKey, JSON.stringify(user));
  }

  return json({ ok: true }, 200);
}

// ── Cancel a Lemon Squeezy subscription via API ────────────────
// Stops auto-renewal immediately. Pro access (trial or paid) is left
// untouched and continues until proExpiresAt, exactly as advertised.
async function cancelSubscription(env, body) {
  if (!env.AUTH_KV) return { error: 'Not configured.' };
  const token = String(body.token || '');
  const email = String(body.email || '').toLowerCase().trim();
  if (!token || !email) return { error: 'Missing data.' };
  const sessionRaw = await env.AUTH_KV.get('session:' + token);
  if (!sessionRaw) return { error: 'Session expired. Please sign in again.' };
  const session = JSON.parse(sessionRaw);
  if (session.email !== email) return { error: 'Unauthorised.' };

  const raw = await env.AUTH_KV.get('user:' + email);
  if (!raw) return { error: 'Account not found.' };
  const user = JSON.parse(raw);

  if (user.lsSubscriptionId && env.LS_API_KEY) {
    try {
      const resp = await fetch(`https://api.lemonsqueezy.com/v1/subscriptions/${user.lsSubscriptionId}`, {
        method: 'PATCH',
        headers: {
          'Authorization': `Bearer ${env.LS_API_KEY}`,
          'Content-Type': 'application/vnd.api+json',
          'Accept': 'application/vnd.api+json',
        },
        body: JSON.stringify({ data: { type: 'subscriptions', id: String(user.lsSubscriptionId), attributes: { cancelled: true } } }),
      });
      if (!resp.ok) return { error: 'Could not cancel with our payment provider. Please email support@scoremychances.com.' };
    } catch (e) {
      return { error: 'Could not cancel with our payment provider. Please email support@scoremychances.com.' };
    }
  }

  user.proAutoRenew = false;
  await env.AUTH_KV.put('user:' + email, JSON.stringify(user));
  return { ok: true };
}

async function authLogin(env, body) {
  if (!env.AUTH_KV) return { error: 'Auth not configured (AUTH_KV not bound).' };
  const email    = sanitize(String(body.email    || ''), 200).toLowerCase().trim();
  const password = String(body.password || '');
  if (!email || !password) return { error: 'Missing email or password.' };
  const raw = await env.AUTH_KV.get('user:' + email);
  if (!raw) return { error: 'Incorrect email or password.' };
  const user = JSON.parse(raw);
  const hash = await hashPassword(password, user.salt);
  if (hash !== user.passwordHash) return { error: 'Incorrect email or password.' };
  const token = makeToken();
  await env.AUTH_KV.put('session:' + token, JSON.stringify({ email, expiresAt: Date.now() + 30*24*60*60*1000 }), { expirationTtl: 30*24*60*60 });

  // Strip Pro access if the billing period has ended
  let proExpired = false;
  if (user.pro === true && user.proExpiresAt && user.proExpiresAt < Date.now()) {
    user.pro = false;
    proExpired = true;
    await env.AUTH_KV.put('user:' + email, JSON.stringify(user));
  }

  // Owner account always gets Pro (for testing)
  const isOwner = email === 'aak99239@gmail.com';
  return {
    ok: true, name: user.name, email, token,
    pro: isOwner || user.pro === true,
    proPlan: user.proPlan || null,
    proExpiresAt: user.proExpiresAt || null,
    proExpired: !isOwner && proExpired,
    proIsTrial: user.proIsTrial === true,
    proAutoRenew: user.proAutoRenew !== false,
    proTrialUsed: user.proTrialUsed === true,
  };
}

async function authSaveProfile(env, body) {
  if (!env.AUTH_KV) return { ok: true }; // silently succeed if not configured
  const token   = String(body.token   || '');
  const email   = String(body.email   || '').toLowerCase().trim();
  const profile = body.profile;
  if (!token || !email || !profile) return { error: 'Missing data.' };
  // Verify session
  const sessionRaw = await env.AUTH_KV.get('session:' + token);
  if (!sessionRaw) return { error: 'Session expired. Please sign in again.' };
  const session = JSON.parse(sessionRaw);
  if (session.email !== email) return { error: 'Unauthorised.' };
  // Save profile
  const key = 'profiles:' + email;
  const existing = JSON.parse(await env.AUTH_KV.get(key) || '[]');
  existing.unshift({ ...profile, savedAt: new Date().toISOString() });
  const trimmed = existing.slice(0, 30); // keep last 30
  await env.AUTH_KV.put(key, JSON.stringify(trimmed));
  return { ok: true };
}

// ── Cancellation / general feedback ────────────────────────────
async function submitFeedback(env, body) {
  const email    = sanitize(String(body.email    || 'unknown'), 200);
  const reason   = sanitize(String(body.reason   || ''), 60);
  const feedback = sanitize(String(body.feedback || ''), 2000);
  const context  = sanitize(String(body.context  || ''), 60); // e.g. 'cancel', 'keep'
  if (!feedback && !reason) return { error: 'No feedback provided.' };

  // Store a copy in KV so it's never lost even if email is down
  if (env.AUTH_KV) {
    try {
      const key = 'feedback_log';
      const log = JSON.parse(await env.AUTH_KV.get(key) || '[]');
      log.unshift({ email, reason, feedback, context, ts: Date.now() });
      await env.AUTH_KV.put(key, JSON.stringify(log.slice(0, 200)));
    } catch(e) {}
  }

  // Email the site owner so feedback is seen promptly
  await sendEmail(env, {
    to: 'aak99239@gmail.com',
    subject: `ScoreMyChances feedback${context ? ' (' + context + ')' : ''} — ${reason || 'general'}`,
    html: `<p><strong>From:</strong> ${email}</p><p><strong>Context:</strong> ${context || 'n/a'}</p><p><strong>Reason:</strong> ${reason || 'n/a'}</p><p><strong>Feedback:</strong></p><p>${(feedback || '(none)').replace(/\n/g,'<br>')}</p>`,
  });

  return { ok: true };
}

// ── Main handler ──────────────────────────────────────────────
export default {
  async fetch(request, env) {

    // 1. CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: CORS });
    }

    // 2. Only allow POST or GET (GET is for community DB fetch)
    if (request.method !== 'POST' && request.method !== 'GET') {
      return json({ error: 'Method not allowed' }, 405);
    }

    // 3. Lemon Squeezy webhook — bypass site token, verify with LS signature instead
    const urlObj0 = new URL(request.url);
    if (urlObj0.searchParams.get('action') === 'lspay' && request.method === 'POST') {
      return handleLSWebhook(env, request);
    }

    // 3b. Verify site token — blocks anyone who finds the Worker URL
    const token = request.headers.get('X-Site-Token') || '';
    if (!env.SITE_TOKEN || token !== env.SITE_TOKEN) {
      return json({ error: 'Unauthorised' }, 401);
    }

    // 4. Handle GET community fetch early (before body parsing)
    if (request.method === 'GET') {
      const urlObj = new URL(request.url);
      if (urlObj.searchParams.get('action') === 'community') {
        const result = { universities: [], schools: [], majors: [], companies: [], roles: [] };
        if (env.COMMUNITY_DB) {
          try {
            result.universities = JSON.parse(await env.COMMUNITY_DB.get('university') || '[]');
            result.schools      = JSON.parse(await env.COMMUNITY_DB.get('school')     || '[]');
            result.majors       = JSON.parse(await env.COMMUNITY_DB.get('major')      || '[]');
            result.companies    = JSON.parse(await env.COMMUNITY_DB.get('company')    || '[]');
            result.roles        = JSON.parse(await env.COMMUNITY_DB.get('role')       || '[]');
          } catch(e) {}
        }
        return json(result, 200);
      }
      if (urlObj.searchParams.get('action') === 'maintenance') {
        var maint = { on: false, message: '' };
        if (env.AUTH_KV) {
          try { maint = JSON.parse(await env.AUTH_KV.get('maintenance_mode') || '{"on":false,"message":""}'); } catch(e){}
        }
        return json(maint, 200);
      }
      if (urlObj.searchParams.get('action') === 'stats') {
        var totalAnalyses = 0;
        var totalUsers = 0;
        if (env.COMMUNITY_DB) {
          try { totalAnalyses = parseInt(await env.COMMUNITY_DB.get('total_analyses') || '0'); } catch(e){}
        }
        if (env.AUTH_KV) {
          try { totalUsers = parseInt(await env.AUTH_KV.get('total_users') || '0'); } catch(e){}
        }
        return json({ analyses: totalAnalyses, users: totalUsers }, 200);
      }
      return json({ error: 'Not found' }, 404);
    }

    // Block oversized requests before reading the body
    const contentLength = parseInt(request.headers.get('content-length') || '0');
    if (contentLength > MAX_BODY_BYTES) {
      return json({ error: 'Request too large' }, 413);
    }

    // 5. IP-based rate limiting (15 req / 60 s per IP)
    const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
    const allowed = await checkRateLimit(ip);
    if (!allowed) {
      return json(
        { error: 'Too many requests. Please wait a minute before trying again.' },
        429
      );
    }

    // 6. Parse body
    let body;
    try {
      const raw = await request.text();
      if (raw.length > MAX_BODY_BYTES) return json({ error: 'Request too large' }, 413);
      body = JSON.parse(raw);
    } catch {
      return json({ error: 'Invalid request body' }, 400);
    }

    // 7. Route auth / data actions BEFORE AI input validation
    const action = body.action;
    if (action === 'signup')       return json(await authSignup(env, body, request));
    if (action === 'login')        return json(await authLogin(env, body));
    if (action === 'save_profile') return json(await authSaveProfile(env, body));
    if (action === 'submitFeedback') return json(await submitFeedback(env, body));
    if (action === 'cancel_subscription') return json(await cancelSubscription(env, body));
    if (action === 'contribute') {
      if (env.COMMUNITY_DB) {
        const type  = sanitize(String(body.type  || ''), 20);
        const value = sanitize(String(body.value || ''), 200);
        const allowed = ['university','school','major','company','role'];
        if (type && value && allowed.includes(type)) {
          try {
            const existing = JSON.parse(await env.COMMUNITY_DB.get(type) || '[]');
            const lower = existing.map(e => e.toLowerCase());
            if (!lower.includes(value.toLowerCase())) {
              existing.push(value);
              await env.COMMUNITY_DB.put(type, JSON.stringify(existing));
            }
          } catch(e) {}
        }
      }
      return json({ ok: true });
    }
    if (action === 'getAnalyses') {
      if (!env.AUTH_KV) return json({ ok: true, analyses: [] });
      const token = String(body.token || '');
      const sessionRaw = await env.AUTH_KV.get('session:' + token);
      if (!sessionRaw) return json({ error: 'Session expired.' }, 401);
      const session = JSON.parse(sessionRaw);
      const key = 'profiles:' + session.email;
      const data = JSON.parse(await env.AUTH_KV.get(key) || '[]');
      return json({ ok: true, analyses: data });
    }
    if (action === 'submitReview') {
      const rating = Math.max(1, Math.min(5, parseInt(body.rating, 10) || 0));
      const text   = sanitize(String(body.text || ''), 400).trim();
      const name   = sanitize(String(body.name || 'Anonymous'), 30).trim() || 'Anonymous';
      if (!rating || text.length < 10) {
        return json({ error: 'Please provide a rating and at least 10 characters.' }, 400);
      }
      if (env.COMMUNITY_DB) {
        try {
          const reviews = JSON.parse(await env.COMMUNITY_DB.get('reviews') || '[]');
          reviews.unshift({ rating, text, name, ts: Date.now() });
          await env.COMMUNITY_DB.put('reviews', JSON.stringify(reviews.slice(0, 200)));
        } catch (e) {}
      }
      return json({ ok: true });
    }
    if (action === 'getReviews') {
      if (!env.COMMUNITY_DB) return json({ ok: true, reviews: [] });
      const all = JSON.parse(await env.COMMUNITY_DB.get('reviews') || '[]');
      const top = all
        .filter(r => r.rating >= 4)
        .sort((a, b) => (b.rating - a.rating) || (b.ts - a.ts))
        .slice(0, 10);
      return json({ ok: true, reviews: top });
    }

    // 8. Validate & sanitise AI inputs
    let { userMessage, systemPrompt, history } = body;
    if (!userMessage || !systemPrompt) {
      return json({ error: 'Missing required fields' }, 400);
    }

    userMessage   = sanitize(String(userMessage),   MAX_MSG_CHARS);
    systemPrompt  = sanitize(String(systemPrompt),  MAX_PROMPT_CHARS);
    // Sanitise conversation history (for multi-turn Essay Workshop / Interview Sim)
    const cleanHistory = Array.isArray(history) ? history.slice(-12).map(m => ({
      role: ['user','assistant'].includes(m.role) ? m.role : 'user',
      content: sanitize(String(m.content || ''), 2000)
    })) : [];

    if (userMessage.length < 10) {
      return json({ error: 'Message too short' }, 400);
    }

    // 9. Call Groq
    let groqRes;
    try {
      groqRes = await fetch('https://api.groq.com/openai/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${env.GROQ_API_KEY}`,
        },
        body: JSON.stringify({
          model: 'llama-3.3-70b-versatile',
          messages: [
            { role: 'system', content: systemPrompt },
            ...cleanHistory,
            { role: 'user',   content: userMessage  },
          ],
          max_tokens: 2400,
          temperature: 0.7,
        }),
      });
    } catch (e) {
      return json({ error: 'Could not reach AI service. Please try again.' }, 502);
    }

    const groqData = await groqRes.json();

    if (!groqRes.ok) {
      return json({ error: 'AI service error. Please try again shortly.' }, 502);
    }

    const text = groqData?.choices?.[0]?.message?.content || '';

    // Increment analysis counter (non-blocking)
    if (env.COMMUNITY_DB) {
      env.COMMUNITY_DB.get('total_analyses').then(function(val) {
        var count = parseInt(val || '0') + 1;
        env.COMMUNITY_DB.put('total_analyses', String(count));
      }).catch(function(){});
    }

    return json({ text }, 200);
  },
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...CORS, 'Content-Type': 'application/json' },
  });
}
