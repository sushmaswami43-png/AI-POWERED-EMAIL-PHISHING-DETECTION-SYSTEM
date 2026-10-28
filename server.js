require('dotenv').config();
const express = require('express');
const path = require('path');
const { createClient } = require('@supabase/supabase-js');
const { analyze } = require('./detector');

const sb = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);
const app = express();
app.use(express.json({ limit: '200kb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Public keys only (anon key is safe for the browser)
app.get('/api/config', (_q, r) => r.json({ url: process.env.SUPABASE_URL, anon: process.env.SUPABASE_ANON_KEY }));

// Verifies the Supabase login token sent by the frontend
const auth = async (req, res, next) => {
  const t = (req.headers.authorization || '').replace('Bearer ', '');
  const { data, error } = await sb.auth.getUser(t);
  if (error || !data.user) return res.status(401).json({ error: 'Please log in again.' });
  req.user = data.user;
  next();
};

app.post('/api/scan', auth, async (req, res) => {
  const text = (req.body.text || '').trim();
  if (text.length < 20) return res.status(400).json({ error: 'Paste at least 20 characters of email content.' });
  const r = analyze(text);
  const { data, error } = await sb.from('scans').insert({
    user_id: req.user.id, email_text: text.slice(0, 5000),
    verdict: r.verdict, risk_score: r.score, keywords: r.keywords, reasons: r.reasons
  }).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.get('/api/history', auth, async (req, res) => {
  const { data, error } = await sb.from('scans').select('*').eq('user_id', req.user.id)
    .order('created_at', { ascending: false }).limit(100);
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.delete('/api/history/:id', auth, async (req, res) => {
  const { error } = await sb.from('scans').delete().eq('id', req.params.id).eq('user_id', req.user.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ ok: true });
});

app.get('/api/stats', auth, async (req, res) => {
  const { data, error } = await sb.from('scans').select('verdict,risk_score,keywords,created_at')
    .eq('user_id', req.user.id).order('created_at', { ascending: false }).limit(500);
  if (error) return res.status(500).json({ error: error.message });
  const c = { Safe: 0, Suspicious: 0, Phishing: 0 }, kw = {}, days = [];
  for (let i = 6; i >= 0; i--) {
    const d = new Date(); d.setDate(d.getDate() - i);
    days.push({ key: d.toISOString().slice(0, 10), label: d.toLocaleDateString('en-IN', { day: 'numeric', month: 'short' }), count: 0 });
  }
  let sum = 0;
  data.forEach(s => {
    c[s.verdict]++; sum += s.risk_score;
    (s.keywords || []).forEach(k => kw[k] = (kw[k] || 0) + 1);
    const d = days.find(x => x.key === s.created_at.slice(0, 10)); if (d) d.count++;
  });
  res.json({ total: data.length, ...c, avg: data.length ? Math.round(sum / data.length) : 0, days,
    keywords: Object.entries(kw).sort((a, b) => b[1] - a[1]).slice(0, 6) });
});

app.listen(process.env.PORT || 3000, () => console.log('PhishGuard running on http://localhost:' + (process.env.PORT || 3000)));
