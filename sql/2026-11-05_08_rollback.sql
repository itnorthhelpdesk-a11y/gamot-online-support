-- =====================================================================
-- ROLLBACK para sa 2026-11-05_08_branch_it_position.sql
-- Ibabalik ang set_branch_admin sa YAKAP IT lang.
-- Ibalik muna ang dating index.html bago ito patakbuhin.
-- =====================================================================

CREATE OR REPLACE FUNCTION public.set_branch_admin(p_username text, p_make_admin boolean, p_performed_by text DEFAULT NULL::text)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path = public, extensions
AS $function$
DECLARE
  v_branch TEXT;
  v_facility TEXT;
  v_caller public.users;
BEGIN
  -- BAGO (2b): global ADMIN lang ang puwedeng mag-assign/mag-revoke ng Branch Admin
  v_caller := _current_caller(ARRAY['ADMIN']);
  IF v_caller.id IS NOT NULL THEN
    p_performed_by := v_caller.username;
  END IF;

  SELECT branch, facility INTO v_branch, v_facility FROM users WHERE UPPER(username) = UPPER(p_username);

  -- tanging YAKAP IT lang ang puwedeng maging Branch Admin (napagkasunduan sa PhilHealth)
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
