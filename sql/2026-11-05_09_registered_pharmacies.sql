-- =====================================================================
-- Listahan ng registered na pharmacy para sa PhilHealth staff.
-- Isang row bawat accreditation no. na may kahit isang APPROVED account.
-- Walang username, email, o PIN na ibinabalik.
-- Staff/Branch Admin = sariling branch lang; ADMIN = lahat.
-- Patakbuhin ito BAGO i-deploy ang bagong index.html.
-- =====================================================================

CREATE OR REPLACE FUNCTION public.get_registered_pharmacies()
RETURNS JSON
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions
AS $$
DECLARE
  v_caller public.users;
  result JSON;
BEGIN
  v_caller := _current_caller(ARRAY['ADMIN', 'BRANCH_ADMIN', 'STAFF', 'BAS']);

  SELECT json_agg(row_to_json(t) ORDER BY t.branch, t.facility) INTO result
  FROM (
    SELECT accreditation_no, MAX(facility) AS facility, MAX(branch) AS branch
    FROM users
    WHERE account_type = 'PHARMACY'
      AND status = 'APPROVED'
      AND NULLIF(accreditation_no, '') IS NOT NULL
      AND (v_caller.role = 'ADMIN' OR UPPER(branch) = UPPER(COALESCE(v_caller.branch, '__NONE__')))
    GROUP BY accreditation_no
  ) t;

  RETURN COALESCE(result, '[]'::json);
END;
$$;
