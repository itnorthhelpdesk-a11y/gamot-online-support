-- =====================================================================
-- EGOS: Iisang PIN, puwedeng mag-account sa higit sa isang pharmacy
-- Petsa: 2026-11-24
--
-- PAANO GUMAGANA:
--   - Magkahiwalay na account (users row) bawat pharmacy, may sariling
--     accreditation, email, NDA/attachment, role at status.
--   - Unang account: username = PIN (gaya ng dati).
--     Susunod na account: username = PIN@ACCREDITATION (hal. 123456789012@P92039188).
--     Nananatiling UNIQUE ang username sa database.
--   - LOGIN: PIN at password pa rin. Kung higit sa isa ang approved na
--     pharmacy, ibabalik ng server ang listahan para pumili ang user.
--   - ISANG PASSWORD bawat PIN: kapag napalitan ang password ng isang
--     account, sabay na napapalitan ang iba (trigger), naka-log sa
--     account_audit_trail, at nala-logout ang ibang session nila.
--   - REGISTRATION ng bagong pharmacy gamit ang PIN na may account na:
--     kailangan ang KASALUKUYANG password, ibang email, at ibang accreditation.
--   - APPROVAL: Branch Admin (hindi Pharmacy Admin) ang nag-a-approve kapag
--     may iba pang account ang PIN. Kasama sa Pending list ang ibang
--     pharmacy/branch na hawak ng PIN na iyon.
--   - Hindi na puwedeng mag-reset ng password ang Pharmacy Admin para sa
--     ganitong account (maaapektuhan ang ibang pharmacy); Branch Admin na.
--
-- WALANG BINAGO SA DATA ng kasalukuyang mga account.
-- ROLLBACK: 2026-11-24_17_rollback.sql
-- =====================================================================

BEGIN;

-- ---------- 1. Helper: PIN ng isang pharmacy username ----------
CREATE OR REPLACE FUNCTION public._pharmacy_pin(p_username TEXT)
RETURNS TEXT
LANGUAGE sql
IMMUTABLE
SET search_path = public
AS $$
  SELECT UPPER(split_part(COALESCE(p_username, ''), '@', 1));
$$;
REVOKE ALL ON FUNCTION public._pharmacy_pin(TEXT) FROM PUBLIC, anon, authenticated;


-- ---------- 2. Trigger: iisang password sa lahat ng account ng PIN ----------
CREATE OR REPLACE FUNCTION public._sync_linked_pharmacy_password()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions
AS $$
DECLARE
  r RECORD;
  v_by TEXT;
BEGIN
  IF NEW.account_type IS DISTINCT FROM 'PHARMACY' OR pg_trigger_depth() > 1 THEN
    RETURN NULL;
  END IF;

  v_by := COALESCE(_session_username(), NEW.username);

  FOR r IN
    UPDATE users
    SET password = NEW.password,
        failed_login_count = NEW.failed_login_count,
        locked_until = NEW.locked_until
    WHERE account_type = 'PHARMACY'
      AND id <> NEW.id
      AND _pharmacy_pin(username) = _pharmacy_pin(NEW.username)
      AND password IS DISTINCT FROM NEW.password
    RETURNING id, username, branch
  LOOP
    UPDATE sessions SET revoked_at = NOW() WHERE user_id = r.id AND revoked_at IS NULL;
    PERFORM log_account_audit(r.username, 'PASSWORD_SYNCED', v_by, r.branch,
      'Password changed together with linked account ' || NEW.username || ' (same PIN).');
  END LOOP;

  RETURN NULL;
END;
$$;
REVOKE ALL ON FUNCTION public._sync_linked_pharmacy_password() FROM PUBLIC, anon, authenticated;

DROP TRIGGER IF EXISTS users_sync_linked_pharmacy_password ON public.users;
CREATE TRIGGER users_sync_linked_pharmacy_password
  AFTER UPDATE OF password ON public.users
  FOR EACH ROW
  WHEN (NEW.password IS DISTINCT FROM OLD.password)
  EXECUTE FUNCTION public._sync_linked_pharmacy_password();


-- ---------- 3. Login: PIN + password, at pagpili ng pharmacy ----------
-- Bagong optional na input_accreditation; gumagana pa rin ang lumang tawag (2 args).
DROP FUNCTION IF EXISTS public.check_staff_login(text, text);

CREATE OR REPLACE FUNCTION public.check_staff_login(input_username text, input_password text, input_accreditation text DEFAULT NULL)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path = public, extensions
AS $function$
DECLARE
  v_input TEXT := UPPER(TRIM(COALESCE(input_username, '')));
  v_accred TEXT := NULLIF(UPPER(TRIM(COALESCE(input_accreditation, ''))), '');
  v_exact public.users;
  v_ids BIGINT[];
  v_match BIGINT[];
  v_locked TIMESTAMPTZ;
  v_max_attempts INT := 5;
  v_lockout_minutes INT := 15;
  v_new_count INT;
  v_approved INT;
  v_pharmacies JSON;
  user_record public.users;
  v_token TEXT;
BEGIN
  SELECT * INTO v_exact FROM users WHERE UPPER(username) = v_input;

  IF v_exact.id IS NOT NULL AND (v_exact.account_type IS DISTINCT FROM 'PHARMACY' OR position('@' IN v_input) > 0) THEN
    -- Staff account, o buong username (PIN@ACCRED) ang tinype: iyon lang
    v_ids := ARRAY[v_exact.id];
  ELSIF position('@' IN v_input) = 0 AND v_input <> '' THEN
    -- PIN: lahat ng pharmacy account ng PIN na ito
    SELECT array_agg(id) INTO v_ids
    FROM users
    WHERE account_type = 'PHARMACY' AND _pharmacy_pin(username) = v_input;
  END IF;

  IF v_ids IS NULL OR cardinality(v_ids) = 0 THEN
    PERFORM _log_login_event(input_username, 'LOGIN_FAILED', 'Unknown username.');
    RETURN json_build_object('success', false, 'message', 'Invalid credentials.');
  END IF;

  -- Naka-lock (sabay-sabay ang lock ng mga account ng iisang PIN)
  SELECT MAX(locked_until) INTO v_locked FROM users WHERE id = ANY(v_ids);
  IF v_locked IS NOT NULL AND v_locked > NOW() THEN
    PERFORM _log_login_event(v_input, 'LOGIN_LOCKED', 'Attempt while account is locked.');
    RETURN json_build_object(
      'success', false,
      'message', 'Too many failed login attempts. Please try again in ' ||
                 GREATEST(1, CEIL(EXTRACT(EPOCH FROM (v_locked - NOW())) / 60))::INT || ' minute(s).'
    );
  END IF;

  SELECT array_agg(id) INTO v_match
  FROM users
  WHERE id = ANY(v_ids) AND password = crypt(input_password, password);

  IF v_match IS NULL THEN
    SELECT COALESCE(MAX(failed_login_count), 0) + 1 INTO v_new_count FROM users WHERE id = ANY(v_ids);

    UPDATE users
    SET failed_login_count = v_new_count,
        locked_until = CASE
          WHEN v_new_count >= v_max_attempts
          THEN NOW() + (v_lockout_minutes || ' minutes')::INTERVAL
          ELSE locked_until
        END
    WHERE id = ANY(v_ids);

    PERFORM _log_login_event(v_input, 'LOGIN_FAILED',
      'Wrong password (attempt ' || v_new_count || ' of ' || v_max_attempts || ').' ||
      CASE WHEN v_new_count >= v_max_attempts THEN ' Account locked for ' || v_lockout_minutes || ' minutes.' ELSE '' END);

    RETURN json_build_object('success', false, 'message', 'Invalid credentials.');
  END IF;

  -- Tamang password: i-reset ang counter
  UPDATE users SET failed_login_count = 0, locked_until = NULL WHERE id = ANY(v_ids);

  SELECT COUNT(*) INTO v_approved
  FROM users
  WHERE id = ANY(v_match) AND status = 'APPROVED'
    AND (v_accred IS NULL OR UPPER(accreditation_no) = v_accred);

  IF v_approved = 0 THEN
    IF v_accred IS NOT NULL THEN
      RETURN json_build_object('success', false, 'message', 'The selected pharmacy is not available for this account. Please sign in again.');
    END IF;

    SELECT * INTO user_record
    FROM users
    WHERE id = ANY(v_match)
    ORDER BY CASE status WHEN 'PENDING' THEN 1 WHEN 'DEACTIVATED' THEN 2 ELSE 3 END, id
    LIMIT 1;

    IF user_record.status = 'PENDING' THEN
      PERFORM _log_login_event(user_record.username, 'LOGIN_BLOCKED', 'Account still PENDING.');
      RETURN json_build_object('success', false, 'message', 'Your account is still awaiting admin approval.');
    END IF;

    IF user_record.status = 'DEACTIVATED' THEN
      PERFORM _log_login_event(user_record.username, 'LOGIN_BLOCKED', 'Account DEACTIVATED.');
      RETURN json_build_object('success', false, 'message', 'Your account has been deactivated. Please contact your Pharmacy Admin.');
    END IF;

    PERFORM _log_login_event(user_record.username, 'LOGIN_BLOCKED', 'Account REJECTED.');
    RETURN json_build_object('success', false, 'message', 'Your registration was declined. Please contact the admin.');
  END IF;

  -- Higit sa isang approved na pharmacy: papiliin muna
  IF v_approved > 1 THEN
    SELECT json_agg(json_build_object(
             'accreditation_no', accreditation_no,
             'facility', facility,
             'branch', branch,
             'role', role
           ) ORDER BY facility, accreditation_no) INTO v_pharmacies
    FROM users
    WHERE id = ANY(v_match) AND status = 'APPROVED';

    RETURN json_build_object(
      'success', false,
      'choose_pharmacy', true,
      'message', 'Please select which pharmacy to open.',
      'pharmacies', v_pharmacies
    );
  END IF;

  SELECT * INTO user_record
  FROM users
  WHERE id = ANY(v_match) AND status = 'APPROVED'
    AND (v_accred IS NULL OR UPPER(accreditation_no) = v_accred)
  LIMIT 1;

  -- Session token (ang hash lang ang ise-save)
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
    'username', user_record.username,
    'role', user_record.role,
    'facility', user_record.facility,
    'branch', user_record.branch,
    'idNo', user_record.id_no,
    'account_type', user_record.account_type,
    'accreditation_no', user_record.accreditation_no
  );
END;
$function$;


-- ---------- 4. Registration: pinapayagan ang parehong PIN sa ibang pharmacy ----------
CREATE OR REPLACE FUNCTION public.register_user(p_username text, p_password text, p_account_type text, p_facility text, p_branch text, p_accreditation_no text, p_email text, p_attachment_link text, p_philhealth_pin text, p_employee_id_no text)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path = public, extensions
AS $function$
DECLARE
  v_existing INT;
  v_existing_email INT;
  v_role TEXT;
  v_recent_attempts INT;
  v_daily_attempts INT;
  v_username TEXT := UPPER(TRIM(COALESCE(p_username, '')));
  v_accred TEXT := UPPER(TRIM(COALESCE(p_accreditation_no, '')));
  v_linked_hash TEXT;
  v_linked_list TEXT;
BEGIN
  IF position('@' IN v_username) > 0 THEN
    RETURN json_build_object('success', false, 'message', 'The username must not contain "@".');
  END IF;

  -- May account na ba ang PIN na ito sa ibang pharmacy?
  IF UPPER(p_account_type) = 'PHARMACY' THEN
    IF EXISTS (
      SELECT 1 FROM users
      WHERE account_type = 'PHARMACY'
        AND _pharmacy_pin(username) = v_username
        AND status != 'REJECTED'
        AND UPPER(accreditation_no) = v_accred
    ) THEN
      RETURN json_build_object('success', false, 'message', 'This PhilHealth Identification Number (PIN) is already registered for this pharmacy (accreditation no.). If this is your account, please use "Forgot Password" instead.');
    END IF;

    SELECT password INTO v_linked_hash
    FROM users
    WHERE account_type = 'PHARMACY'
      AND _pharmacy_pin(username) = v_username
      AND status != 'REJECTED'
    ORDER BY (status = 'APPROVED') DESC, id
    LIMIT 1;
  END IF;

  IF v_linked_hash IS NOT NULL THEN
    -- Dagdag na pharmacy: patunayang siya ang may-ari ng PIN
    IF v_linked_hash IS DISTINCT FROM crypt(COALESCE(p_password, ''), v_linked_hash) THEN
      RETURN json_build_object('success', false, 'message', 'This PIN already has an EGOS account in another pharmacy. To add this pharmacy, enter your CURRENT EGOS password in the Password field (one password is used for all your pharmacies).');
    END IF;
    IF v_accred = '' THEN
      RETURN json_build_object('success', false, 'message', 'Please enter the Facility Accreditation No. of the pharmacy you are adding.');
    END IF;
  ELSE
    IF LENGTH(p_password) < 8 THEN
      RETURN json_build_object('success', false, 'message', 'Password must be at least 8 characters long.');
    END IF;

    IF p_password !~ '[A-Z]' THEN
      RETURN json_build_object('success', false, 'message', 'Password must contain at least one uppercase letter.');
    END IF;

    IF p_password !~ '[a-z]' THEN
      RETURN json_build_object('success', false, 'message', 'Password must contain at least one lowercase letter.');
    END IF;

    IF p_password !~ '[0-9]' THEN
      RETURN json_build_object('success', false, 'message', 'Password must contain at least one number.');
    END IF;
  END IF;

  -- ang server na mismo ang nagche-check na na-verify ang email
  IF NOT EXISTS (
    SELECT 1 FROM registration_email_verifications
    WHERE LOWER(email) = LOWER(p_email)
      AND verified_at > NOW() - INTERVAL '2 hours'
  ) THEN
    RETURN json_build_object('success', false, 'message', 'Please verify your email address first (the verification is valid for 2 hours).');
  END IF;

  -- hindi kasama ang REJECTED (declined) accounts sa email uniqueness check
  SELECT COUNT(*) INTO v_existing_email
  FROM users
  WHERE LOWER(email) = LOWER(p_email)
    AND status != 'REJECTED';

  IF v_existing_email > 0 THEN
    RETURN json_build_object('success', false, 'message', 'This email address is already registered to another account. Please use a different email (each pharmacy account needs its own email), or use "Forgot Password" if this is your account.');
  END IF;

  SELECT COUNT(*) INTO v_recent_attempts
  FROM registration_attempts
  WHERE LOWER(email) = LOWER(p_email) AND attempted_at > NOW() - INTERVAL '10 minutes';

  IF v_recent_attempts > 0 THEN
    RETURN json_build_object('success', false, 'message', 'Please wait a few minutes before trying to register again with this email.');
  END IF;

  SELECT COUNT(*) INTO v_daily_attempts
  FROM registration_attempts
  WHERE LOWER(email) = LOWER(p_email) AND attempted_at > NOW() - INTERVAL '24 hours';

  IF v_daily_attempts >= 5 THEN
    RETURN json_build_object('success', false, 'message', 'Too many registration attempts with this email today. Please try again tomorrow or contact support.');
  END IF;

  INSERT INTO registration_attempts (email) VALUES (p_email);

  -- Dagdag na pharmacy: PIN@ACCRED ang username kung gamit na ang PIN mismo
  IF v_linked_hash IS NOT NULL AND EXISTS (
    SELECT 1 FROM users WHERE UPPER(username) = v_username AND status != 'REJECTED'
  ) THEN
    v_username := v_username || '@' || v_accred;
  END IF;

  -- hindi kasama ang REJECTED accounts sa username uniqueness check
  SELECT COUNT(*) INTO v_existing
  FROM users
  WHERE UPPER(username) = v_username
    AND status != 'REJECTED';

  IF v_existing > 0 THEN
    IF UPPER(p_account_type) = 'STAFF' THEN
      RETURN json_build_object('success', false, 'message', 'This PhilHealth Employee ID No. is already registered to another account. If this is your account, please use "Forgot Password" instead.');
    ELSE
      RETURN json_build_object('success', false, 'message', 'This PhilHealth Identification Number (PIN) is already registered to another account. If this is your account, please use "Forgot Password" instead.');
    END IF;
  END IF;

  v_role := CASE WHEN UPPER(p_account_type) = 'STAFF' THEN 'STAFF' ELSE 'USER' END;

  -- Declined account na nagre-register ulit: gamitin ang dating row (UNIQUE ang username sa DB)
  UPDATE users
  SET password = COALESCE(v_linked_hash, crypt(p_password, gen_salt('bf'))),
      role = v_role,
      facility = UPPER(p_facility),
      branch = UPPER(p_branch),
      account_type = p_account_type,
      status = 'PENDING',
      accreditation_no = UPPER(p_accreditation_no),
      email = p_email,
      attachment_link = p_attachment_link,
      philhealth_pin = p_philhealth_pin,
      employee_id_no = p_employee_id_no,
      decline_reason = NULL
  WHERE UPPER(username) = v_username
    AND status = 'REJECTED';

  IF FOUND THEN
    PERFORM log_account_audit(v_username, 'RE_REGISTERED', v_username, UPPER(p_branch), 'Declined account registered again with a new password and details.');
  ELSE
    BEGIN
      INSERT INTO users (username, password, role, facility, branch, account_type, status, accreditation_no, email, attachment_link, philhealth_pin, employee_id_no)
      VALUES (v_username, COALESCE(v_linked_hash, crypt(p_password, gen_salt('bf'))), v_role, UPPER(p_facility), UPPER(p_branch), p_account_type, 'PENDING', UPPER(p_accreditation_no), p_email, p_attachment_link, p_philhealth_pin, p_employee_id_no);
    EXCEPTION WHEN unique_violation THEN
      RETURN json_build_object('success', false, 'message', 'This ID or email is already registered to another account. If this is your account, please use "Forgot Password" instead.');
    END;
  END IF;

  IF v_linked_hash IS NOT NULL THEN
    SELECT string_agg(username || ' (' || COALESCE(accreditation_no, '—') || ', ' || COALESCE(branch, '—') || ', ' || status || ')', '; ' ORDER BY id)
      INTO v_linked_list
    FROM users
    WHERE account_type = 'PHARMACY'
      AND _pharmacy_pin(username) = _pharmacy_pin(v_username)
      AND UPPER(username) <> v_username
      AND status != 'REJECTED';

    PERFORM log_account_audit(v_username, 'REGISTERED_ADDITIONAL_PHARMACY', v_username, UPPER(p_branch),
      'Same PIN registered for another pharmacy. Other accounts: ' || COALESCE(v_linked_list, '—'));
  END IF;

  -- gamit na ang verification (hindi na puwedeng gamitin ulit)
  DELETE FROM registration_email_verifications WHERE LOWER(email) = LOWER(p_email);

  RETURN json_build_object('success', true, 'additional_pharmacy', v_linked_hash IS NOT NULL);
END;
$function$;


-- ---------- 5. Pending accounts ng Branch Admin: kasama ang may ibang pharmacy ----------
CREATE OR REPLACE FUNCTION public.get_pending_users(p_branch text DEFAULT NULL::text)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path = public, extensions
AS $function$
DECLARE
  result JSON;
  v_caller public.users;
BEGIN
  v_caller := _current_caller(ARRAY['ADMIN', 'BRANCH_ADMIN']);
  IF v_caller.id IS NOT NULL THEN
    p_branch := CASE WHEN v_caller.role = 'ADMIN' THEN NULL ELSE COALESCE(v_caller.branch, '__NONE__') END;
  END IF;

  SELECT json_agg(row_to_json(u)) INTO result
  FROM (
    SELECT u.username, u.account_type, u.facility, u.branch, u.created_at, u.attachment_link, u.accreditation_no,
           (SELECT json_agg(json_build_object(
                     'username', o.username,
                     'accreditation_no', o.accreditation_no,
                     'facility', o.facility,
                     'branch', o.branch,
                     'role', o.role,
                     'status', o.status
                   ) ORDER BY o.id)
            FROM users o
            WHERE u.account_type = 'PHARMACY'
              AND o.account_type = 'PHARMACY'
              AND o.id <> u.id
              AND _pharmacy_pin(o.username) = _pharmacy_pin(u.username)
              AND o.status != 'REJECTED') AS other_accounts
    FROM users u
    WHERE u.status = 'PENDING'
      AND (p_branch IS NULL OR p_branch = '' OR UPPER(u.branch) = UPPER(p_branch))
      AND (
        u.account_type != 'PHARMACY'
        OR NOT EXISTS (
          SELECT 1 FROM users pa
          WHERE pa.accreditation_no = u.accreditation_no
            AND pa.role = 'PHARMACY_ADMIN'
            AND pa.status = 'APPROVED'
        )
        -- may account na sa ibang pharmacy: Branch Admin ang mag-a-approve
        OR EXISTS (
          SELECT 1 FROM users o
          WHERE o.account_type = 'PHARMACY'
            AND o.id <> u.id
            AND _pharmacy_pin(o.username) = _pharmacy_pin(u.username)
            AND o.status != 'REJECTED'
        )
      )
    ORDER BY u.created_at
  ) u;

  RETURN COALESCE(result, '[]'::json);
END;
$function$;


-- ---------- 6. Pending Staff ng Pharmacy Admin: HINDI kasama ang may ibang pharmacy ----------
CREATE OR REPLACE FUNCTION public.get_pending_pharmacy_staff(p_accreditation_no text)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path = public, extensions
AS $function$
DECLARE
  result JSON;
  v_caller public.users;
BEGIN
  v_caller := _current_caller(ARRAY['PHARMACY_ADMIN']);
  IF v_caller.id IS NOT NULL THEN
    p_accreditation_no := COALESCE(v_caller.accreditation_no, '__NONE__');
  END IF;

  SELECT json_agg(row_to_json(u)) INTO result
  FROM (
    SELECT u.username, u.facility, u.branch, u.created_at, u.attachment_link
    FROM users u
    WHERE u.status = 'PENDING'
      AND u.account_type = 'PHARMACY'
      AND u.accreditation_no = p_accreditation_no
      AND NOT EXISTS (
        SELECT 1 FROM users o
        WHERE o.account_type = 'PHARMACY'
          AND o.id <> u.id
          AND _pharmacy_pin(o.username) = _pharmacy_pin(u.username)
          AND o.status != 'REJECTED'
      )
    ORDER BY u.created_at
  ) u;

  RETURN COALESCE(result, '[]'::json);
END;
$function$;


-- ---------- 7. approve_pharmacy_staff: bawal sa may ibang pharmacy ----------
CREATE OR REPLACE FUNCTION public.approve_pharmacy_staff(p_username text, p_decision text, p_decline_reason text, p_accreditation_no text, p_performed_by text DEFAULT NULL::text)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path = public, extensions
AS $function$
DECLARE
  v_id INT;
  v_new_id_no TEXT;
  v_target_accred TEXT;
  v_branch TEXT;
  v_caller public.users;
BEGIN
  v_caller := _current_caller(ARRAY['PHARMACY_ADMIN']);
  IF v_caller.id IS NOT NULL THEN
    p_performed_by := v_caller.username;
    p_accreditation_no := COALESCE(v_caller.accreditation_no, '__NONE__');
  END IF;

  SELECT id, accreditation_no, branch INTO v_id, v_target_accred, v_branch
  FROM users WHERE UPPER(username) = UPPER(p_username);

  IF v_target_accred IS DISTINCT FROM p_accreditation_no THEN
    RETURN json_build_object('success', false, 'message', 'Not authorized for this account.');
  END IF;

  IF EXISTS (
    SELECT 1 FROM users o
    WHERE o.account_type = 'PHARMACY'
      AND o.id <> v_id
      AND _pharmacy_pin(o.username) = _pharmacy_pin(p_username)
      AND o.status != 'REJECTED'
  ) THEN
    RETURN json_build_object('success', false, 'message', 'This PIN also has an account in another pharmacy. The Branch Admin must review this registration.');
  END IF;

  IF UPPER(p_decision) = 'APPROVED' THEN
    v_new_id_no := 'EOGS-' || LPAD(v_id::TEXT, 5, '0');
    UPDATE users SET status = 'APPROVED', id_no = v_new_id_no, role = 'USER'
    WHERE UPPER(username) = UPPER(p_username);

    IF p_performed_by IS NOT NULL THEN
      PERFORM log_account_audit(p_username, 'APPROVED', p_performed_by, v_branch, 'Approved by Pharmacy Admin.');
    END IF;
  ELSE
    UPDATE users SET status = UPPER(p_decision), decline_reason = p_decline_reason
    WHERE UPPER(username) = UPPER(p_username);

    IF p_performed_by IS NOT NULL THEN
      PERFORM log_account_audit(p_username, UPPER(p_decision), p_performed_by, v_branch, p_decline_reason);
    END IF;
  END IF;

  RETURN json_build_object('success', true);
END;
$function$;


-- ---------- 8. pharmacy_admin_reset_password: bawal sa may ibang pharmacy ----------
CREATE OR REPLACE FUNCTION public.pharmacy_admin_reset_password(p_username text, p_accreditation_no text, p_new_password text, p_performed_by text DEFAULT NULL::text)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path = public, extensions
AS $function$
DECLARE
  v_id BIGINT;
  v_target_accred TEXT;
  v_branch TEXT;
  v_caller public.users;
BEGIN
  v_caller := _current_caller(ARRAY['PHARMACY_ADMIN']);
  IF v_caller.id IS NOT NULL THEN
    p_performed_by := v_caller.username;
    p_accreditation_no := COALESCE(v_caller.accreditation_no, '__NONE__');
  END IF;

  SELECT id, accreditation_no, branch INTO v_id, v_target_accred, v_branch FROM users WHERE UPPER(username) = UPPER(p_username);

  IF v_target_accred IS DISTINCT FROM p_accreditation_no THEN
    RETURN json_build_object('success', false, 'message', 'Not authorized for this account.');
  END IF;

  -- Iisa ang password ng lahat ng pharmacy ng PIN: Branch Admin na ang magre-reset
  IF EXISTS (
    SELECT 1 FROM users o
    WHERE o.account_type = 'PHARMACY'
      AND o.id <> v_id
      AND _pharmacy_pin(o.username) = _pharmacy_pin(p_username)
      AND o.status != 'REJECTED'
  ) THEN
    RETURN json_build_object('success', false, 'message', 'This person also has an account in another pharmacy, so the password is shared. Please ask your Branch Admin to reset it, or the user can use "Forgot Password".');
  END IF;

  UPDATE users SET password = crypt(p_new_password, gen_salt('bf')) WHERE UPPER(username) = UPPER(p_username);

  IF p_performed_by IS NOT NULL THEN
    PERFORM log_account_audit(p_username, 'PASSWORD_RESET', p_performed_by, v_branch, 'Password reset by Pharmacy Admin.');
  END IF;

  RETURN json_build_object('success', true);
END;
$function$;

COMMIT;

-- ---------- PAG-CHECK (patakbuhin pagkatapos) ----------
-- 1) Dapat 1 row lang ang check_staff_login, at may 3 argument:
--    SELECT proname, pg_get_function_arguments(oid) FROM pg_proc WHERE proname = 'check_staff_login';
-- 2) Dapat may trigger:
--    SELECT tgname FROM pg_trigger WHERE tgname = 'users_sync_linked_pharmacy_password';
