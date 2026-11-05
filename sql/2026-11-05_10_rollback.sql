-- =====================================================================
-- ROLLBACK para sa 2026-11-05_10_pharmacy_branch_from_prefix.sql
-- Ibabalik ang branch sa pinili ng pharmacy noong nag-register.
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
