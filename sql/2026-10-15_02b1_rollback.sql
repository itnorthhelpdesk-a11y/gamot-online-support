-- =====================================================================
-- ROLLBACK para sa 2026-10-15_02b1_account_admin_functions.sql
-- Patakbuhin LAMANG kung may nasira pagkatapos ng Hakbang 2b Grupo 1.
-- Ibinabalik ang 10 function sa dating bersyon (kinuha sa live database
-- noong 2026-10-15) at binubura ang _current_caller helper.
-- =====================================================================

BEGIN;

-- ----- get_pending_users(p_branch text)
ALTER FUNCTION public.get_pending_users(p_branch text) RESET search_path;
CREATE OR REPLACE FUNCTION public.get_pending_users(p_branch text DEFAULT NULL::text)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
AS $function$
DECLARE
  result JSON;
BEGIN
  SELECT json_agg(row_to_json(u)) INTO result
  FROM (
    SELECT username, account_type, facility, branch, created_at, attachment_link
    FROM users u
    WHERE status = 'PENDING'
      AND (p_branch IS NULL OR p_branch = '' OR UPPER(branch) = UPPER(p_branch))
      AND (
        account_type != 'PHARMACY'
        OR NOT EXISTS (
          SELECT 1 FROM users pa
          WHERE pa.accreditation_no = u.accreditation_no
            AND pa.role = 'PHARMACY_ADMIN'
            AND pa.status = 'APPROVED'
        )
      )
    ORDER BY created_at
  ) u;

  RETURN COALESCE(result, '[]'::json);
END;
$function$;

-- ----- approve_user(p_username text, p_decision text, p_decline_reason text, p_role text, p_performed_by text)
ALTER FUNCTION public.approve_user(p_username text, p_decision text, p_decline_reason text, p_role text, p_performed_by text) RESET search_path;
CREATE OR REPLACE FUNCTION public.approve_user(p_username text, p_decision text, p_decline_reason text DEFAULT NULL::text, p_role text DEFAULT NULL::text, p_performed_by text DEFAULT NULL::text)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
AS $function$
DECLARE
  v_id INT;
  v_new_id_no TEXT;
  v_account_type TEXT;
  v_accreditation TEXT;
  v_branch TEXT;
  v_existing_pharmacy_admin INT;
  v_new_role TEXT;
BEGIN
  SELECT branch INTO v_branch FROM users WHERE UPPER(username) = UPPER(p_username);

  IF UPPER(p_decision) = 'APPROVED' THEN
    SELECT id, account_type, accreditation_no INTO v_id, v_account_type, v_accreditation
    FROM users WHERE UPPER(username) = UPPER(p_username);

    v_new_id_no := 'EOGS-' || LPAD(v_id::TEXT, 5, '0');

    IF v_account_type = 'PHARMACY' THEN
      IF p_role IN ('USER', 'PHARMACY_ADMIN') THEN
        v_new_role := p_role;
      ELSE
        SELECT COUNT(*) INTO v_existing_pharmacy_admin
        FROM users
        WHERE accreditation_no = v_accreditation
          AND role = 'PHARMACY_ADMIN'
          AND status = 'APPROVED';

        v_new_role := CASE WHEN v_existing_pharmacy_admin = 0 THEN 'PHARMACY_ADMIN' ELSE 'USER' END;
      END IF;

      -- BAGO: kahit anong paraan nalaman ang bagong role, kung PHARMACY_ADMIN ito,
      -- siguraduhing DEMOTED muna sa USER ang kahit sinong existing PHARMACY_ADMIN sa parehong facility.
      -- Isa lang talaga ang PHARMACY_ADMIN kada accreditation number, walang exception.
      IF v_new_role = 'PHARMACY_ADMIN' THEN
        UPDATE users
        SET role = 'USER'
        WHERE accreditation_no = v_accreditation
          AND role = 'PHARMACY_ADMIN'
          AND status = 'APPROVED'
          AND UPPER(username) != UPPER(p_username);
      END IF;

      UPDATE users
      SET status = 'APPROVED', id_no = v_new_id_no, role = v_new_role
      WHERE UPPER(username) = UPPER(p_username);
    ELSE
      UPDATE users
      SET status = 'APPROVED', id_no = v_new_id_no
      WHERE UPPER(username) = UPPER(p_username);
    END IF;

    IF p_performed_by IS NOT NULL THEN
      PERFORM log_account_audit(p_username, 'APPROVED', p_performed_by, v_branch, 'Account approved.');
    END IF;
  ELSE
    UPDATE users
    SET status = UPPER(p_decision), decline_reason = p_decline_reason
    WHERE UPPER(username) = UPPER(p_username);

    IF p_performed_by IS NOT NULL THEN
      PERFORM log_account_audit(p_username, UPPER(p_decision), p_performed_by, v_branch, p_decline_reason);
    END IF;
  END IF;

  RETURN json_build_object('success', true);
END;
$function$;

-- ----- get_approved_accounts_by_type(p_account_type text, p_branch text)
ALTER FUNCTION public.get_approved_accounts_by_type(p_account_type text, p_branch text) RESET search_path;
CREATE OR REPLACE FUNCTION public.get_approved_accounts_by_type(p_account_type text, p_branch text DEFAULT NULL::text)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
AS $function$
DECLARE
  result JSON;
BEGIN
  SELECT json_agg(row_to_json(u) ORDER BY u.branch, u.username) INTO result
  FROM (
    SELECT username, facility, branch, role, account_type, email, status, employee_id_no, accreditation_no
    FROM users
    WHERE account_type = p_account_type
      AND status IN ('APPROVED', 'DEACTIVATED')
      AND (p_branch IS NULL OR p_branch = '' OR UPPER(branch) = UPPER(p_branch))
  ) u;

  RETURN COALESCE(result, '[]'::json);
END;
$function$;

-- ----- set_branch_admin(p_username text, p_make_admin boolean, p_performed_by text)
ALTER FUNCTION public.set_branch_admin(p_username text, p_make_admin boolean, p_performed_by text) RESET search_path;
CREATE OR REPLACE FUNCTION public.set_branch_admin(p_username text, p_make_admin boolean, p_performed_by text DEFAULT NULL::text)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
AS $function$
DECLARE
  v_branch TEXT;
  v_facility TEXT;
BEGIN
  SELECT branch, facility INTO v_branch, v_facility FROM users WHERE UPPER(username) = UPPER(p_username);

  -- BAGO: tanging YAKAP IT lang ang puwedeng maging Branch Admin (napagkasunduan sa PhilHealth)
  IF p_make_admin AND UPPER(v_facility) != 'YAKAP IT' THEN
    RETURN json_build_object('success', false, 'message', 'Only staff under the YAKAP IT department may be designated as Branch Admin.');
  END IF;

  IF p_make_admin THEN
    UPDATE users SET role = 'BRANCH_ADMIN' WHERE UPPER(username) = UPPER(p_username);
  ELSE
    UPDATE users SET role = 'STAFF' WHERE UPPER(username) = UPPER(p_username);
  END IF;

  IF p_performed_by IS NOT NULL THEN
    PERFORM log_account_audit(p_username, CASE WHEN p_make_admin THEN 'MADE_BRANCH_ADMIN' ELSE 'REVOKED_BRANCH_ADMIN' END, p_performed_by, v_branch, NULL);
  END IF;

  RETURN json_build_object('success', true);
END;
$function$;

-- ----- set_pharmacy_admin(p_username text, p_make_admin boolean, p_requesting_branch text, p_performed_by text)
ALTER FUNCTION public.set_pharmacy_admin(p_username text, p_make_admin boolean, p_requesting_branch text, p_performed_by text) RESET search_path;
CREATE OR REPLACE FUNCTION public.set_pharmacy_admin(p_username text, p_make_admin boolean, p_requesting_branch text DEFAULT NULL::text, p_performed_by text DEFAULT NULL::text)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
AS $function$
DECLARE
  v_target_branch TEXT;
  v_target_accred TEXT;
  v_target_status TEXT;
BEGIN
  SELECT branch, accreditation_no, status INTO v_target_branch, v_target_accred, v_target_status
  FROM users WHERE UPPER(username) = UPPER(p_username);

  IF v_target_accred IS NULL THEN
    RETURN json_build_object('success', false, 'message', 'Account not found.');
  END IF;

  IF p_requesting_branch IS NOT NULL AND p_requesting_branch != ''
     AND UPPER(v_target_branch) IS DISTINCT FROM UPPER(p_requesting_branch) THEN
    RETURN json_build_object('success', false, 'message', 'Not authorized for this account.');
  END IF;

  IF p_make_admin AND v_target_status != 'APPROVED' THEN
    RETURN json_build_object('success', false, 'message', 'Only an active (APPROVED) staff member can be made Pharmacy Admin.');
  END IF;

  IF p_make_admin THEN
    UPDATE users
    SET role = 'USER'
    WHERE accreditation_no = v_target_accred
      AND role = 'PHARMACY_ADMIN'
      AND status = 'APPROVED'
      AND UPPER(username) != UPPER(p_username);

    UPDATE users SET role = 'PHARMACY_ADMIN' WHERE UPPER(username) = UPPER(p_username);
  ELSE
    UPDATE users SET role = 'USER' WHERE UPPER(username) = UPPER(p_username);
  END IF;

  IF p_performed_by IS NOT NULL THEN
    PERFORM log_account_audit(p_username, CASE WHEN p_make_admin THEN 'MADE_PHARMACY_ADMIN' ELSE 'REVOKED_PHARMACY_ADMIN' END, p_performed_by, v_target_branch, NULL);
  END IF;

  RETURN json_build_object('success', true);
END;
$function$;

-- ----- update_staff_email_by_admin(p_username text, p_requesting_branch text, p_new_email text, p_performed_by text)
ALTER FUNCTION public.update_staff_email_by_admin(p_username text, p_requesting_branch text, p_new_email text, p_performed_by text) RESET search_path;
CREATE OR REPLACE FUNCTION public.update_staff_email_by_admin(p_username text, p_requesting_branch text, p_new_email text, p_performed_by text DEFAULT NULL::text)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
AS $function$
DECLARE
  v_target_branch TEXT;
BEGIN
  SELECT branch INTO v_target_branch FROM users WHERE UPPER(username) = UPPER(p_username);

  IF p_requesting_branch IS NOT NULL AND p_requesting_branch != '' 
     AND UPPER(v_target_branch) IS DISTINCT FROM UPPER(p_requesting_branch) THEN
    RETURN json_build_object('success', false, 'message', 'Not authorized for this account.');
  END IF;

  UPDATE users SET email = p_new_email WHERE UPPER(username) = UPPER(p_username);

  IF p_performed_by IS NOT NULL THEN
    PERFORM log_account_audit(p_username, 'EMAIL_UPDATED', p_performed_by, v_target_branch, 'Email updated by Admin.');
  END IF;

  RETURN json_build_object('success', true);
END;
$function$;

-- ----- update_staff_employee_id_by_admin(p_username text, p_requesting_branch text, p_new_employee_id text, p_performed_by text)
ALTER FUNCTION public.update_staff_employee_id_by_admin(p_username text, p_requesting_branch text, p_new_employee_id text, p_performed_by text) RESET search_path;
CREATE OR REPLACE FUNCTION public.update_staff_employee_id_by_admin(p_username text, p_requesting_branch text, p_new_employee_id text, p_performed_by text DEFAULT NULL::text)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
AS $function$
DECLARE
  v_target_branch TEXT;
  v_existing INT;
BEGIN
  SELECT branch INTO v_target_branch FROM users WHERE UPPER(username) = UPPER(p_username);

  IF p_requesting_branch IS NOT NULL AND p_requesting_branch != ''
     AND UPPER(v_target_branch) IS DISTINCT FROM UPPER(p_requesting_branch) THEN
    RETURN json_build_object('success', false, 'message', 'Not authorized for this account.');
  END IF;

  SELECT COUNT(*) INTO v_existing
  FROM users
  WHERE UPPER(username) = UPPER(p_new_employee_id)
    AND UPPER(username) != UPPER(p_username);

  IF v_existing > 0 THEN
    RETURN json_build_object('success', false, 'message', 'This Employee ID is already used by another account.');
  END IF;

  UPDATE users
  SET employee_id_no = p_new_employee_id,
      username = UPPER(p_new_employee_id)
  WHERE UPPER(username) = UPPER(p_username);

  IF p_performed_by IS NOT NULL THEN
    PERFORM log_account_audit(UPPER(p_new_employee_id), 'EMPLOYEE_ID_UPDATED', p_performed_by, v_target_branch, 'Employee ID (and login username) changed from ' || p_username || ' to ' || UPPER(p_new_employee_id) || '.');
  END IF;

  RETURN json_build_object('success', true);
END;
$function$;

-- ----- set_staff_active_status_by_admin(p_username text, p_requesting_branch text, p_active boolean, p_performed_by text)
ALTER FUNCTION public.set_staff_active_status_by_admin(p_username text, p_requesting_branch text, p_active boolean, p_performed_by text) RESET search_path;
CREATE OR REPLACE FUNCTION public.set_staff_active_status_by_admin(p_username text, p_requesting_branch text, p_active boolean, p_performed_by text DEFAULT NULL::text)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
AS $function$
DECLARE
  v_target_branch TEXT;
BEGIN
  SELECT branch INTO v_target_branch FROM users WHERE UPPER(username) = UPPER(p_username);

  IF p_requesting_branch IS NOT NULL AND p_requesting_branch != ''
     AND UPPER(v_target_branch) IS DISTINCT FROM UPPER(p_requesting_branch) THEN
    RETURN json_build_object('success', false, 'message', 'Not authorized for this account.');
  END IF;

  UPDATE users
  SET status = CASE WHEN p_active THEN 'APPROVED' ELSE 'DEACTIVATED' END
  WHERE UPPER(username) = UPPER(p_username);

  IF p_performed_by IS NOT NULL THEN
    PERFORM log_account_audit(p_username, CASE WHEN p_active THEN 'REACTIVATED' ELSE 'DEACTIVATED' END, p_performed_by, v_target_branch, 'Changed by Admin.');
  END IF;

  RETURN json_build_object('success', true);
END;
$function$;

-- ----- admin_reset_password(p_username text, p_requesting_branch text, p_new_password text, p_performed_by text)
ALTER FUNCTION public.admin_reset_password(p_username text, p_requesting_branch text, p_new_password text, p_performed_by text) RESET search_path;
CREATE OR REPLACE FUNCTION public.admin_reset_password(p_username text, p_requesting_branch text, p_new_password text, p_performed_by text DEFAULT NULL::text)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
AS $function$
DECLARE
  v_target_branch TEXT;
BEGIN
  SELECT branch INTO v_target_branch FROM users WHERE UPPER(username) = UPPER(p_username);

  IF v_target_branch IS NULL THEN
    RETURN json_build_object('success', false, 'message', 'Account not found.');
  END IF;

  IF p_requesting_branch IS NOT NULL AND p_requesting_branch != ''
     AND UPPER(v_target_branch) IS DISTINCT FROM UPPER(p_requesting_branch) THEN
    RETURN json_build_object('success', false, 'message', 'Not authorized for this account.');
  END IF;

  UPDATE users SET password = crypt(p_new_password, gen_salt('bf')) WHERE UPPER(username) = UPPER(p_username);

  IF p_performed_by IS NOT NULL THEN
    PERFORM log_account_audit(p_username, 'PASSWORD_RESET', p_performed_by, v_target_branch, 'Password reset by admin.');
  END IF;

  RETURN json_build_object('success', true);
END;
$function$;

-- ----- get_account_audit_trail(p_branch text)
ALTER FUNCTION public.get_account_audit_trail(p_branch text) RESET search_path;
CREATE OR REPLACE FUNCTION public.get_account_audit_trail(p_branch text DEFAULT NULL::text)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
AS $function$
DECLARE
  result JSON;
BEGIN
  SELECT json_agg(row_to_json(t) ORDER BY t.performed_at DESC) INTO result
  FROM (
    SELECT username_affected, action, performed_by_username, performed_by_employee_id, performed_at, details, branch
    FROM account_audit_trail
    WHERE (p_branch IS NULL OR p_branch = '' OR UPPER(branch) = UPPER(p_branch))
    LIMIT 300
  ) t;

  RETURN COALESCE(result, '[]'::json);
END;
$function$;

DROP FUNCTION IF EXISTS public._current_caller(TEXT[]);

COMMIT;
