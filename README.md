# PhishGuard - AI-Powered Email Phishing Detection System

Stack: HTML/CSS/JS + Chart.js | Node.js + Express | Supabase (Database + Auth)

## Setup
1. supabase.com par new project banao.
2. SQL Editor me `schema.sql` run karo (table `scans` + security policies).
3. Authentication -> Providers -> Email: testing ke liye "Confirm email" OFF kar do.
4. Settings -> API se URL, anon key, service_role key copy karo.
5. `cp .env.example .env` karke teeno values paste karo.
6. `npm install` then `npm start` -> http://localhost:3000

## Kaise kaam karta hai
- Login/Register: Supabase Auth (browser se).
- Scan: frontend token bhejta hai -> Express token verify karta hai -> `detector.js` risk score nikalta hai -> result Supabase `scans` table me save hota hai.
- Dashboard: `/api/stats` se counts, 7-day trend, verdict split aur top keywords charts me dikhte hain.
- service_role key sirf `.env` me rakho, kabhi frontend ya GitHub par mat daalo.
