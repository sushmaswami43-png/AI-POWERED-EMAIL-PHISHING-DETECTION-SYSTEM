// Rule-based phishing detection engine with weighted risk scoring (0-100)
const RULES = [
  { re: /urgent|immediately|within 24 hours|act now|final notice|expires? (today|soon)|last chance/i, w: 12, why: 'Creates false urgency' },
  { re: /verify your (account|identity|password)|confirm your (account|identity|password|details)|update your (payment|billing|account)|re-?activate/i, w: 18, why: 'Asks you to verify or update account details' },
  { re: /password|\botp\b|\bpin\b|cvv|card number|\bssn\b|social security|bank account/i, w: 15, why: 'Requests sensitive information' },
  { re: /account (has been |is )?(suspended|locked|limited|compromised|disabled)|unusual (sign.?in|activity)|security alert/i, w: 15, why: 'Threatens account suspension' },
  { re: /you('ve| have)? won|lottery|prize|claim your|gift card|free (iphone|gift)|refund|inheritance/i, w: 14, why: 'Offers prizes or money' },
  { re: /click (here|below|the link)|log ?in (here|now)/i, w: 8, why: 'Pushes you to click a link' },
  { re: /dear (customer|user|member|client)|valued customer/i, w: 8, why: 'Uses a generic greeting' },
  { re: /\.(exe|scr|vbs|js)\b|enable (macros|content)/i, w: 12, why: 'Mentions a risky attachment or macro' }
];
const SHORT = /^(bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly|is\.gd|cutt\.ly|rb\.gy)$/i;
const BADTLD = /\.(xyz|top|click|tk|ml|ga|cf|gq|work|zip|support|monster)$/i;
const BRANDS = ['paypal', 'amazon', 'microsoft', 'apple', 'google', 'netflix', 'sbi', 'hdfc', 'icici', 'paytm', 'facebook', 'instagram'];

function analyze(text) {
  let score = 0;
  const reasons = [], keywords = new Set();
  const add = (w, why) => { score += w; if (!reasons.includes(why)) reasons.push(why); };

  for (const r of RULES) {
    const m = text.match(r.re);
    if (m) { add(r.w, r.why); keywords.add(m[0].toLowerCase().trim()); }
  }

  const urls = text.match(/(https?:\/\/|www\.)[^\s<>"')]+/gi) || [];
  const hosts = [];
  for (const u of urls) {
    let h;
    try { h = new URL(/^www\./i.test(u) ? 'http://' + u : u).hostname; } catch { continue; }
    hosts.push(h);
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(h)) add(20, 'Link uses a raw IP address');
    if (SHORT.test(h)) add(12, 'Link is shortened and hides its destination');
    if (u.includes('@')) add(15, 'Link contains an @ symbol to disguise the real site');
    if (h.includes('xn--')) add(15, 'Link uses look-alike (punycode) characters');
    if ((h.match(/-/g) || []).length >= 3 || h.split('.').length >= 5) add(10, 'Link has an unusually long or hyphenated domain');
    if (BADTLD.test(h)) add(10, 'Link uses a domain ending often abused by scammers');
    if (/^http:\/\//i.test(u)) add(6, 'Link is not encrypted (http)');
  }

  const lower = text.toLowerCase();
  const brand = BRANDS.find(b => new RegExp('\\b' + b + '\\b').test(lower));
  if (brand && hosts.length && !hosts.some(h => h === brand + '.com' || h.endsWith('.' + brand + '.com')))
    add(15, `Mentions ${brand} but links to a different site`);

  if ((text.match(/!/g) || []).length >= 3) add(5, 'Excessive exclamation marks');
  const letters = text.replace(/[^a-z]/gi, '');
  if (letters.length > 40 && text.replace(/[^A-Z]/g, '').length / letters.length > 0.35) add(5, 'Too much capitalised text');

  score = Math.min(100, score);
  const verdict = score >= 60 ? 'Phishing' : score >= 30 ? 'Suspicious' : 'Safe';
  if (!reasons.length) reasons.push('No common phishing patterns found');
  return { score, verdict, reasons, keywords: [...keywords].slice(0, 10) };
}
module.exports = { analyze };
