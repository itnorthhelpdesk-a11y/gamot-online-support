-- =====================================================================
-- EGOS Hakbang 3b: ayos sa reset_password_with_otp
-- Petsa: 2026-10-15
--
-- PROBLEMA: kapag naubos ang 5 hula, BINUBURA ang code. Ang cooldown
-- (2 minuto) at daily limit (5) ng send-reset-otp ay nagbibilang ng
-- code na nasa table, kaya puwedeng humingi agad ng bago nang paulit-ulit.
-- AYOS: i-expire na lang (expires_at = NOW()) para mabilang pa rin.
--
-- LIGTAS PATAKBUHIN KAHIT KAILAN (parehong parameters).
-- ROLLBACK: patakbuhin ulit ang 2026-10-15_03_otp_audit_idno.sql
-- =====================================================================

BEGIN;

CREATE OR REPLACE FUNCTION public.reset_password_with_otp(p_username text, p_otp text, p_new_password text)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path = public, extensions
AS $function$
DECLARE
  v_req RECORD;
  v_user RECORD;
  v_max_attempts INT := 5;
BEGIN
  -- Ang pinakabagong code lang ang tinatanggap
  SELECT * INTO v_req
  FROM password_reset_requests
  WHERE UPPER(username) = UPPER(p_username)
    AND expires_at > NOW()
  ORDER BY created_at DESC
  LIMIT 1;

  IF NOT FOUND THEN
    RETURN json_build_object('success', false, 'message', 'Invalid or expired code.');
  END IF;

  IF v_req.otp IS DISTINCT FROM p_otp THEN
    UPDATE password_reset_requests SET attempts = attempts + 1 WHERE id = v_req.id;

    IF v_req.attempts + 1 >= v_max_attempts THEN
      -- BAGO: i-expire (hindi burahin) para mabilang pa rin sa cooldown at daily limit
      UPDATE password_reset_requests SET expires_at = NOW()
      WHERE UPPER(username) = UPPER(p_username) AND expires_at > NOW();
      RETURN json_build_object('success', false, 'message', 'Too many incorrect attempts. Please request a new code.');
    END IF;

    RETURN json_build_object('success', false, 'message', 'Invalid or expired code.');
  END IF;

  -- Parehong password rules ng registration (hindi pa nauubos ang code kapag mali ito)
  IF LENGTH(COALESCE(p_new_password, '')) < 8
     OR p_new_password !~ '[A-Z]' OR p_new_password !~ '[a-z]' OR p_new_password !~ '[0-9]' THEN
    RETURN json_build_object('success', false, 'message', 'Password must be at least 8 characters and include an uppercase letter, a lowercase letter, and a number.');
  END IF;

  SELECT id, username, branch INTO v_user FROM users WHERE UPPER(username) = UPPER(p_username);

  IF NOT FOUND THEN
    RETURN json_build_object('success', false, 'message', 'Invalid or expired code.');
  END IF;

  UPDATE users
  SET password = crypt(p_new_password, gen_salt('bf')),
      failed_login_count = 0,
      locked_until = NULL
  WHERE id = v_user.id;

  -- BAGO: i-expire ang lahat ng code ng user (hindi burahin; para sa daily limit)
  UPDATE password_reset_requests SET expires_at = NOW()
  WHERE UPPER(username) = UPPER(p_username) AND expires_at > NOW();

  -- I-logout ang lahat ng bukas na session ng user
  UPDATE sessions SET revoked_at = NOW() WHERE user_id = v_user.id AND revoked_at IS NULL;

  PERFORM log_account_audit(v_user.username, 'PASSWORD_RESET_SELF', v_user.username, v_user.branch,
    'Password reset by the account holder using an emailed code.');

  RETURN json_build_object('success', true);
END;
$function$;

COMMIT;
