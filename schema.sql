-- Run this in Supabase -> SQL Editor
create table public.scans (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  email_text text not null,
  verdict text not null check (verdict in ('Safe','Suspicious','Phishing')),
  risk_score int not null check (risk_score between 0 and 100),
  keywords jsonb not null default '[]',
  reasons jsonb not null default '[]',
  created_at timestamptz not null default now()
);
create index on public.scans (user_id, created_at desc);
alter table public.scans enable row level security;
create policy "own scans select" on public.scans for select using (auth.uid() = user_id);
create policy "own scans insert" on public.scans for insert with check (auth.uid() = user_id);
create policy "own scans delete" on public.scans for delete using (auth.uid() = user_id);
