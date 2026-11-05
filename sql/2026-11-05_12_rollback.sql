-- Rollback ng 2026-11-05_12_account_attachments.sql
-- Hindi nito ibinabalik ang dating attachment_link ng mga account na nadagdagan na;
-- nasa account_audit_trail (ATTACHMENT_ADDED) ang dating link ng bawat isa.

DROP FUNCTION IF EXISTS public.add_account_attachment(text, text, text);

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
    SELECT username, facility, branch, role, account_type, email, status, employee_id_no, accreditation_no
    FROM users
    WHERE account_type = p_account_type
      AND status IN ('APPROVED', 'DEACTIVATED')
      AND (p_branch IS NULL OR p_branch = '' OR UPPER(branch) = UPPER(p_branch))
  ) u;

  RETURN COALESCE(result, '[]'::json);
END;
$function$;
