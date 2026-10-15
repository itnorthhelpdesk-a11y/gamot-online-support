-- =====================================================================
-- ROLLBACK para sa 2026-10-15_02c_require_session_token.sql
-- Ibinabalik ang _current_caller() sa "transition" mode:
-- walang token = lumang paraan (para gumana ulit ang lumang index.html).
-- Gamitin LAMANG kung hindi makagamit ang users pagkatapos ng 2c.
-- =====================================================================

BEGIN;

CREATE OR REPLACE FUNCTION public._current_caller(p_allowed_roles TEXT[])
 RETURNS public.users
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path = public, extensions
AS $function$
DECLARE
  v_token TEXT;
  v_hash TEXT;
  v_user public.users;
BEGIN
  BEGIN
    v_token := current_setting('request.headers', true)::JSON->>'x-egos-session';
  EXCEPTION WHEN others THEN
    v_token := NULL;
  END;

  -- PANSAMANTALA (hanggang Hakbang 2c): walang token = lumang paraan
  IF v_token IS NULL OR v_token = '' THEN
    RETURN NULL;
  END IF;

  v_hash := encode(digest(v_token, 'sha256'), 'hex');

  SELECT u.* INTO v_user
  FROM sessions s
  JOIN users u ON u.id = s.user_id
  WHERE s.token_hash = v_hash
    AND s.revoked_at IS NULL
    AND s.expires_at > NOW()
    AND s.last_seen_at > NOW() - INTERVAL '2 hours';

  IF NOT FOUND OR v_user.status IS DISTINCT FROM 'APPROVED' THEN
    RAISE EXCEPTION 'SESSION_EXPIRED';
  END IF;

  IF p_allowed_roles IS NOT NULL AND NOT (v_user.role = ANY(p_allowed_roles)) THEN
    RAISE EXCEPTION 'NOT_AUTHORIZED';
  END IF;

  UPDATE sessions SET last_seen_at = NOW() WHERE token_hash = v_hash;

  RETURN v_user;
END;
$function$;

COMMIT;
