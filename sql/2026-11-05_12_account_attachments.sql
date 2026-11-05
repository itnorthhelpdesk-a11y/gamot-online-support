-- =====================================================================
-- Manage Accounts: makikita at madadagdagan ng admin ang attachment
-- ng approved na account (para sa audit, at kapag direktang isinumite
-- sa admin ang file).
-- Global ADMIN = lahat; BRANCH_ADMIN = sariling branch lang.
-- Naka-log sa account_audit_trail ang bawat dagdag, kasama ang dahilan
-- at ang dating file. Hindi binubura ang dating file sa Storage.
-- Patakbuhin ito BAGO i-deploy ang bagong index.html.
-- =====================================================================

CREATE OR REPLACE FUNCTION public.get_approved_accounts_by_type(p_account_type text, p_branch text DEFAULT NULL::text)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path = public, extensions
AS $function$
DECLARE
  result JSON;
  v_caller public.users;
BEGIN
  -- BAGO (2b): kapag may session token, ang server ang nagtatakda ng branch
  v_caller := _current_caller(ARRAY['ADMIN', 'BRANCH_ADMIN']);
  IF v_caller.id IS NOT NULL THEN
    p_branch := CASE WHEN v_caller.role = 'ADMIN' THEN NULL ELSE COALESCE(v_caller.branch, '__NONE__') END;
  END IF;

  SELECT json_agg(row_to_json(u) ORDER BY u.branch, u.username) INTO result
  FROM (
    SELECT username, facility, branch, role, account_type, email, status, employee_id_no, accreditation_no, attachment_link
    FROM users
    WHERE account_type = p_account_type
      AND status IN ('APPROVED', 'DEACTIVATED')
      AND (p_branch IS NULL OR p_branch = '' OR UPPER(branch) = UPPER(p_branch))
  ) u;

  RETURN COALESCE(result, '[]'::json);
END;
$function$;


CREATE OR REPLACE FUNCTION public.add_account_attachment(p_username text, p_attachment_link text, p_reason text)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path = public, extensions
AS $function$
DECLARE
  v_caller public.users;
  v_target public.users;
  v_file_name TEXT;
BEGIN
  v_caller := _current_caller(ARRAY['ADMIN', 'BRANCH_ADMIN']);

  IF NULLIF(TRIM(p_reason), '') IS NULL THEN
    RETURN json_build_object('success', false, 'message', 'A reason is required.');
  END IF;

  SELECT * INTO v_target FROM users WHERE UPPER(username) = UPPER(p_username);

  IF v_target.id IS NULL OR v_target.status NOT IN ('APPROVED', 'DEACTIVATED') THEN
    RETURN json_build_object('success', false, 'message', 'Account not found.');
  END IF;

  IF v_caller.role <> 'ADMIN'
     AND UPPER(v_target.branch) IS DISTINCT FROM UPPER(COALESCE(v_caller.branch, '__NONE__')) THEN
    RETURN json_build_object('success', false, 'message', 'Not authorized for this account.');
  END IF;

  -- Dapat bagong file ito mula sa upload ng admin, para hindi maituro ang
  -- account sa file ng iba at makuha ang access dito sa pamamagitan ng get-file-url
  v_file_name := substring(p_attachment_link FROM '/storage/v1/object/public/registration-attachments/(admin_[A-Za-z0-9_.-]+)$');

  IF v_file_name IS NULL
     OR NOT EXISTS (SELECT 1 FROM storage.objects WHERE bucket_id = 'registration-attachments' AND name = v_file_name)
     OR EXISTS (SELECT 1 FROM users WHERE attachment_link = p_attachment_link) THEN
    RETURN json_build_object('success', false, 'message', 'Invalid attachment.');
  END IF;

  UPDATE users SET attachment_link = p_attachment_link WHERE id = v_target.id;

  PERFORM log_account_audit(v_target.username, 'ATTACHMENT_ADDED', v_caller.username, v_target.branch,
    'Attachment added by Admin. Reason: ' || TRIM(p_reason) ||
    '. Previous file: ' || COALESCE(NULLIF(v_target.attachment_link, ''), 'none') ||
    '. New file: ' || p_attachment_link);

  RETURN json_build_object('success', true);
END;
$function$;
