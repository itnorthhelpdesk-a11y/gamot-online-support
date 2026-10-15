-- =====================================================================
-- ROLLBACK para sa 2026-10-15_02a_sessions_and_login_audit.sql
-- Patakbuhin LAMANG kung may nasira pagkatapos ng Hakbang 2a.
-- Ibinabalik ang check_staff_login sa dating bersyon (kinuha sa live
-- database noong 2026-10-15) at binubura ang sessions / login_audit.
-- BABALA: mabubura rin ang laman ng login_audit.
-- =====================================================================

BEGIN;

CREATE OR REPLACE FUNCTION public.check_staff_login(input_username text, input_password text)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
AS $function$
DECLARE
  user_record RECORD;
  v_max_attempts INT := 5;
  v_lockout_minutes INT := 15;
BEGIN
  SELECT * INTO user_record
  FROM users
  WHERE UPPER(username) = UPPER(input_username);

  IF user_record IS NULL THEN
    RETURN json_build_object('success', false, 'message', 'Invalid credentials.');
  END IF;

  -- I-check kung naka-lock pa ang account
  IF user_record.locked_until IS NOT NULL AND user_record.locked_until > NOW() THEN
    RETURN json_build_object(
      'success', false,
      'message', 'Too many failed login attempts. Please try again in ' ||
                 GREATEST(1, CEIL(EXTRACT(EPOCH FROM (user_record.locked_until - NOW())) / 60))::INT || ' minute(s).'
    );
  END IF;

  -- I-verify ang password
  IF user_record.password != crypt(input_password, user_record.password) THEN
    -- Maling password: dagdagan ang counter, i-lock kung umabot na sa limit
    UPDATE users
    SET failed_login_count = COALESCE(failed_login_count, 0) + 1,
        locked_until = CASE
          WHEN COALESCE(failed_login_count, 0) + 1 >= v_max_attempts
          THEN NOW() + (v_lockout_minutes || ' minutes')::INTERVAL
          ELSE locked_until
        END
    WHERE UPPER(username) = UPPER(input_username);

    RETURN json_build_object('success', false, 'message', 'Invalid credentials.');
  END IF;

  -- Tamang password: i-reset ang counter
  UPDATE users SET failed_login_count = 0, locked_until = NULL WHERE UPPER(username) = UPPER(input_username);

  IF user_record.status = 'PENDING' THEN
    RETURN json_build_object('success', false, 'message', 'Your account is still awaiting admin approval.');
  END IF;

  IF user_record.status = 'REJECTED' THEN
    RETURN json_build_object('success', false, 'message', 'Your registration was declined. Please contact the admin.');
  END IF;

  IF user_record.status = 'DEACTIVATED' THEN
    RETURN json_build_object('success', false, 'message', 'Your account has been deactivated. Please contact your Pharmacy Admin.');
  END IF;

  RETURN json_build_object(
    'success', true,
    'role', user_record.role,
    'facility', user_record.facility,
    'branch', user_record.branch,
    'idNo', user_record.id_no,
    'account_type', user_record.account_type,
    'accreditation_no', user_record.accreditation_no
  );
END;
$function$;

DROP FUNCTION IF EXISTS public.logout(TEXT);
DROP FUNCTION IF EXISTS public._log_login_event(TEXT, TEXT, TEXT);
DROP TABLE IF EXISTS public.sessions;
DROP TABLE IF EXISTS public.login_audit;

COMMIT;
