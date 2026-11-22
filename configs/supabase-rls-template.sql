-- =============================================================================
-- Supabase Row Level Security (RLS) Audit & Hardening Template (2026)
-- Run Section 1 in Supabase SQL Editor BEFORE every production launch.
-- =============================================================================

-- 1. AUDIT QUERY: List every table in `public` that does NOT have RLS enabled.
--    Expected result before launch: 0 rows.
SELECT
  schemaname,
  tablename,
  rowsecurity
FROM pg_tables
WHERE schemaname = 'public'
  AND rowsecurity = false
ORDER BY tablename;

-- 2. AUDIT QUERY: List tables with RLS enabled but ZERO policies (locked out or misconfigured)
--    or overly permissive USING (true) write policies on anon/public roles.
SELECT
  t.tablename,
  COUNT(p.policyname) AS policy_count
FROM pg_tables t
LEFT JOIN pg_policies p
  ON p.schemaname = t.schemaname AND p.tablename = t.tablename
WHERE t.schemaname = 'public'
  AND t.rowsecurity = true
GROUP BY t.tablename
ORDER BY policy_count ASC, t.tablename;

-- 3. BASELINE USER-OWNED TABLE PATTERN (Example: public.profiles)
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;

-- Optional: Force RLS even for table owners in non-superuser contexts
-- ALTER TABLE public.profiles FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "profiles_select_own" ON public.profiles;
CREATE POLICY "profiles_select_own"
  ON public.profiles
  FOR SELECT
  TO authenticated
  USING (auth.uid() = id);

DROP POLICY IF EXISTS "profiles_insert_own" ON public.profiles;
CREATE POLICY "profiles_insert_own"
  ON public.profiles
  FOR INSERT
  TO authenticated
  WITH CHECK (auth.uid() = id);

DROP POLICY IF EXISTS "profiles_update_own" ON public.profiles;
CREATE POLICY "profiles_update_own"
  ON public.profiles
  FOR UPDATE
  TO authenticated
  USING (auth.uid() = id)
  WITH CHECK (auth.uid() = id);

-- 4. NEVER grant anonymous read/write to billing, audit, or API key tables.
--    Keep `service_role` keys strictly inside server-side routes / Edge Functions.
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM anon;
GRANT USAGE ON SCHEMA public TO anon, authenticated;
