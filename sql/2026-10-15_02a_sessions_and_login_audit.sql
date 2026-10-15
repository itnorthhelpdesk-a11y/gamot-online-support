-- =====================================================================
-- EGOS Security Fix, Hakbang 2a: Session tokens (pundasyon) + Login audit
-- Petsa: 2026-10-15
--
-- ANO ANG GINAGAWA:
--   1. Bagong table na `sessions`: dito naka-save ang (hashed) login tokens.
--   2. Bagong table na `login_audit`: bawat login (tagumpay/bigo/locked) at logout.
--   3. check_staff_login: PAREHONG parameters pa rin, pero nagbabalik na rin
--      ng `token`, at nagla-log sa login_audit.
--   4. Bagong function na `logout(p_token)`: pinapatay ang token.
--
-- LIGTAS SA LIVE SITE:
--   Hindi nagbabago ang parameters ng check_staff_login. Ang live index.html
--   ay hindi pa gumagamit ng token, kaya babalewalain lang nito ang dagdag na
--   `token` field. Wala pang ibang function na humihingi ng token (Hakbang 2b pa).
--
-- TOKEN RULES:
--   - 32 random bytes (hex). SHA-256 hash lang ang naka-save, hindi ang token mismo.
--   - Mag-e-expire: 12 oras mula login, o 2 oras na walang tawag sa server.
--     (Ang 30-minutong auto-logout ay nasa index.html pa rin.)
--
-- ROLLBACK: 2026-10-15_02a_rollback.sql
-- =====================================================================

BEGIN;

-- ---------- 1. SESSIONS ----------
CREATE TABLE public.sessions (
  token_hash   TEXT PRIMARY KEY,
  user_id      BIGINT NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at   TIMESTAMPTZ NOT NULL,
  revoked_at   TIMESTAMPTZ
);
CREATE INDEX sessions_user_id_idx ON public.sessions (user_id);
ALTER TABLE public.sessions ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.sessions FROM PUBLIC, anon, authenticated;

-- ---------- 2. LOGIN AUDIT ----------
CREATE TABLE public.login_audit (
  id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  username    TEXT,
  event       TEXT NOT NULL,   -- LOGIN_SUCCESS, LOGIN_FAILED, LOGIN_LOCKED, LOGIN_BLOCKED, LOGOUT
  details     TEXT,
  ip_address  TEXT,
  user_agent  TEXT,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX login_audit_username_idx ON public.login_audit (username, created_at DESC);
ALTER TABLE public.login_audit ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.login_audit FROM PUBLIC, anon, authenticated;

-- Internal helper: isulat ang isang login event (kasama ang IP at browser kung meron)
CREATE OR REPLACE FUNCTION public._log_login_event(p_username TEXT, p_event TEXT, p_details TEXT DEFAULT NULL)
 RETURNS void
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path = public, extensions
AS $function$
DECLARE
  v_headers JSON;
BEGIN
  BEGIN
    v_headers := current_setting('request.headers', true)::JSON;
  EXCEPTION WHEN others THEN
    v_headers := NULL;
  END;

  INSERT INTO login_audit (username, event, details, ip_address, user_agent)
  VALUES (
    UPPER(p_username),
    p_event,
    p_details,
    split_part(COALESCE(v_headers->>'x-forwarded-for', v_headers->>'x-real-ip', ''), ',', 1),
    LEFT(v_headers->>'user-agent', 300)
  );
END;
$function$;
REVOKE EXECUTE ON FUNCTION public._log_login_event(TEXT, TEXT, TEXT) FROM PUBLIC, anon, authenticated;

-- ---------- 3. LOGIN (parehong parameters; may token at audit na) ----------
CREATE OR REPLACE FUNCTION public.check_staff_login(input_username text, input_password text)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path = public, extensions
AS $function$
DECLARE
  user_record RECORD;
  v_max_attempts INT := 5;
  v_lockout_minutes INT := 15;
  v_new_count INT;
  v_token TEXT;
BEGIN
  SELECT * INTO user_record
  FROM users
  WHERE UPPER(username) = UPPER(input_username);

  IF user_record IS NULL THEN
    PERFORM _log_login_event(input_username, 'LOGIN_FAILED', 'Unknown username.');
    RETURN json_build_object('success', false, 'message', 'Invalid credentials.');
  END IF;

  -- I-check kung naka-lock pa ang account
  IF user_record.locked_until IS NOT NULL AND user_record.locked_until > NOW() THEN
    PERFORM _log_login_event(user_record.username, 'LOGIN_LOCKED', 'Attempt while account is locked.');
    RETURN json_build_object(
      'success', false,
      'message', 'Too many failed login attempts. Please try again in ' ||
                 GREATEST(1, CEIL(EXTRACT(EPOCH FROM (user_record.locked_until - NOW())) / 60))::INT || ' minute(s).'
    );
  END IF;

  -- I-verify ang password
  IF user_record.password != crypt(input_password, user_record.password) THEN
    v_new_count := COALESCE(user_record.failed_login_count, 0) + 1;

    UPDATE users
    SET failed_login_count = v_new_count,
        locked_until = CASE
          WHEN v_new_count >= v_max_attempts
          THEN NOW() + (v_lockout_minutes || ' minutes')::INTERVAL
          ELSE locked_until
        END
    WHERE id = user_record.id;

    PERFORM _log_login_event(user_record.username, 'LOGIN_FAILED',
      'Wrong password (attempt ' || v_new_count || ' of ' || v_max_attempts || ').' ||
      CASE WHEN v_new_count >= v_max_attempts THEN ' Account locked for ' || v_lockout_minutes || ' minutes.' ELSE '' END);

    RETURN json_build_object('success', false, 'message', 'Invalid credentials.');
  END IF;

  -- Tamang password: i-reset ang counter
  UPDATE users SET failed_login_count = 0, locked_until = NULL WHERE id = user_record.id;

  IF user_record.status = 'PENDING' THEN
    PERFORM _log_login_event(user_record.username, 'LOGIN_BLOCKED', 'Account still PENDING.');
    RETURN json_build_object('success', false, 'message', 'Your account is still awaiting admin approval.');
  END IF;

  IF user_record.status = 'REJECTED' THEN
    PERFORM _log_login_event(user_record.username, 'LOGIN_BLOCKED', 'Account REJECTED.');
    RETURN json_build_object('success', false, 'message', 'Your registration was declined. Please contact the admin.');
  END IF;

  IF user_record.status = 'DEACTIVATED' THEN
    PERFORM _log_login_event(user_record.username, 'LOGIN_BLOCKED', 'Account DEACTIVATED.');
    RETURN json_build_object('success', false, 'message', 'Your account has been deactivated. Please contact your Pharmacy Admin.');
  END IF;

  -- BAGO: gumawa ng session token (ang hash lang ang ise-save)
  DELETE FROM sessions
  WHERE user_id = user_record.id
    AND (expires_at < NOW() OR revoked_at IS NOT NULL);

  v_token := encode(gen_random_bytes(32), 'hex');

  INSERT INTO sessions (token_hash, user_id, expires_at)
  VALUES (encode(digest(v_token, 'sha256'), 'hex'), user_record.id, NOW() + INTERVAL '12 hours');

  PERFORM _log_login_event(user_record.username, 'LOGIN_SUCCESS', NULL);

  RETURN json_build_object(
    'success', true,
    'token', v_token,
    'role', user_record.role,
    'facility', user_record.facility,
    'branch', user_record.branch,
    'idNo', user_record.id_no,
    'account_type', user_record.account_type,
    'accreditation_no', user_record.accreditation_no
  );
END;
$function$;

-- ---------- 4. LOGOUT ----------
CREATE OR REPLACE FUNCTION public.logout(p_token TEXT)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path = public, extensions
AS $function$
DECLARE
  v_username TEXT;
BEGIN
  UPDATE sessions s
  SET revoked_at = NOW()
  FROM users u
  WHERE s.token_hash = encode(digest(COALESCE(p_token, ''), 'sha256'), 'hex')
    AND s.revoked_at IS NULL
    AND u.id = s.user_id
  RETURNING u.username INTO v_username;

  IF v_username IS NOT NULL THEN
    PERFORM _log_login_event(v_username, 'LOGOUT', NULL);
  END IF;

  RETURN json_build_object('success', true);
END;
$function$;

COMMIT;

-- ---------- PAG-CHECK (patakbuhin pagkatapos) ----------
-- Dapat may 2 bagong table at false lahat ng anon/auth access:
--   SELECT c.relname,
--          has_table_privilege('anon', c.oid, 'SELECT') AS anon_select,
--          has_table_privilege('authenticated', c.oid, 'SELECT') AS auth_select
--   FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
--   WHERE n.nspname = 'public' AND c.relname IN ('sessions', 'login_audit');
