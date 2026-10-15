-- =====================================================================
-- EGOS Security Fix, Hakbang 2c: GAWING REQUIRED ANG SESSION TOKEN
-- Petsa: 2026-10-15
--
-- *** PATAKBUHIN LAMANG KAPAG ***
--   1. Naka-merge na sa main ang bagong index.html, AT
--   2. Na-deploy na ito ng Netlify (live na ang bagong page), AT
--   3. Na-test na ang login sa LIVE site (hindi local file).
--
-- Kapag pinatakbo ito habang luma pa ang index.html sa Netlify,
-- WALANG makakagamit ng system (lahat ng aksyon ay magbabalik ng
-- "Your session has expired" / SESSION_EXPIRED).
--
-- ANO ANG GINAGAWA:
--   Isang function lang ang binabago: _current_caller().
--   Dati: walang token = lumang paraan (pinagkakatiwalaan ang browser).
--   Ngayon: walang token = SESSION_EXPIRED. Lahat ng 35 protected
--   functions ay sabay-sabay nang sarado.
--
-- EPEKTO SA MGA NAKA-LOGIN: ang mga user na naka-bukas pa ang LUMANG
-- page (bago ang deploy) ay kailangang mag-refresh at mag-login ulit.
--
-- ROLLBACK: 2026-10-15_02c_rollback.sql
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

  -- 2c: REQUIRED na ang token
  IF v_token IS NULL OR v_token = '' THEN
    RAISE EXCEPTION 'SESSION_EXPIRED';
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
