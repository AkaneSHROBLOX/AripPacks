/* Netlify Function : reçoit les événements Stripe et active le Premium dans Firebase.
   Aucune dépendance (rien à installer). Variables d'environnement à créer dans Netlify :
   STRIPE_WEBHOOK_SECRET     = whsec_...   (secret de signature du webhook Stripe)
   FIREBASE_DB_URL           = https://ari-packs-default-rtdb.europe-west1.firebasedatabase.app
   FIREBASE_SERVICE_ACCOUNT  = tout le contenu du fichier JSON du compte de service Firebase */
const crypto = require("crypto");
const OK = { statusCode: 200, body: "ok" };
const DAY = 864e5, PERIOD = 31 * DAY, GRACE = 2 * DAY;

let cached = null;
async function token() {
  if (cached && cached.exp > Date.now() + 60000) return cached.t;
  const sa = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT), now = Math.floor(Date.now() / 1000);
  const b64 = (x) => Buffer.from(x).toString("base64url");
  const h = b64(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const c = b64(JSON.stringify({ iss: sa.client_email, scope: "https://www.googleapis.com/auth/firebase.database https://www.googleapis.com/auth/userinfo.email", aud: "https://oauth2.googleapis.com/token", iat: now, exp: now + 3600 }));
  const sig = crypto.createSign("RSA-SHA256").update(h + "." + c).sign(sa.private_key, "base64url");
  const r = await fetch("https://oauth2.googleapis.com/token", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer", assertion: h + "." + c + "." + sig }) });
  const j = await r.json();
  if (!j.access_token) throw new Error("token Google refusé : " + JSON.stringify(j));
  cached = { t: j.access_token, exp: Date.now() + 3300000 };
  return cached.t;
}
async function fb(method, path, body) {
  const r = await fetch(`${process.env.FIREBASE_DB_URL}/${path}.json`, { method, headers: { Authorization: "Bearer " + (await token()), "content-type": "application/json" }, body: body === undefined ? undefined : JSON.stringify(body) });
  if (!r.ok) throw new Error(`${method} ${path} -> ${r.status}`);
  return r.json();
}
function verify(raw, header, secret) {
  let t, v = [];
  for (const kv of header.split(",")) { const [k, val] = kv.split("="); if (k === "t") t = val; if (k === "v1") v.push(val); }
  if (!t || !secret) return false;
  const exp = crypto.createHmac("sha256", secret).update(t + "." + raw).digest("hex");
  const good = v.some((x) => x.length === exp.length && crypto.timingSafeEqual(Buffer.from(x), Buffer.from(exp)));
  return good && Math.abs(Date.now() / 1000 - Number(t)) < 300;
}
/* le site envoie le pseudo en hexadécimal dans client_reference_id */
function unhex(h) {
  if (!h || !/^([0-9a-f]{2}){2,40}$/.test(h)) return null;
  const k = Buffer.from(h, "hex").toString("utf8");
  return /^[a-z0-9_-]{3,16}$/.test(k) ? k : null;
}

exports.handler = async (event) => {
  if (event.httpMethod !== "POST") return { statusCode: 200, body: "stripe-webhook en ligne" };
  const raw = event.isBase64Encoded ? Buffer.from(event.body, "base64").toString("utf8") : event.body;
  if (!verify(raw, event.headers["stripe-signature"] || "", process.env.STRIPE_WEBHOOK_SECRET)) return { statusCode: 400, body: "signature invalide" };
  const ev = JSON.parse(raw), o = ev.data.object, now = Date.now();
  try {
    if (ev.type === "checkout.session.completed") {
      if (o.payment_status !== "paid" && o.payment_status !== "no_payment_required") return OK;
      const key = unhex(o.client_reference_id);
      if (!key) return OK;
      const cur = (await fb("GET", "premium/" + key)) || {}, active = (cur.until || 0) > now;
      if (o.mode === "subscription") {
        await fb("PUT", "stripe/subs/" + o.subscription, key); /* sert à retrouver le joueur aux renouvellements */
        await fb("PUT", "premium/" + key, { since: active ? cur.since : now, until: Math.max(cur.until || 0, now + PERIOD + GRACE) });
      } else if (o.mode === "payment") { /* paiement unique : +1 mois, sans renouvellement */
        await fb("PUT", "premium/" + key, { since: active ? cur.since : now, until: (active ? cur.until : now) + PERIOD });
      }
    } else if (ev.type === "invoice.paid") {
      const sub = o.subscription || (o.parent && o.parent.subscription_details && o.parent.subscription_details.subscription);
      if (!sub) return OK;
      const key = await fb("GET", "stripe/subs/" + sub);
      if (!key) return { statusCode: 500, body: "abonnement pas encore enregistré, Stripe réessaiera" };
      const end = Math.max(...o.lines.data.map((l) => l.period.end)) * 1000 + GRACE, cur = (await fb("GET", "premium/" + key)) || {};
      await fb("PUT", "premium/" + key, { since: (cur.until || 0) > now ? cur.since : now, until: Math.max(end, now) });
    }
    return OK;
  } catch (e) {
    console.error(e);
    return { statusCode: 500, body: "erreur" }; /* Stripe réessaie automatiquement */
  }
};
