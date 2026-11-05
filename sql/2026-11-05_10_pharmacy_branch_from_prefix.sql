-- =====================================================================
-- Registered Pharmacies: ang branch ay galing na sa accreditation prefix
-- (P91/H91 = NORTH, P92/H92 = SOUTH, P93/H93 = CENTRAL).
-- Kung ibang prefix, ang branch na pinili sa registration ang gagamitin.
-- Staff/Branch Admin = sariling branch lang; ADMIN = lahat.
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
    FROM (
      SELECT accreditation_no, facility,
             CASE
               WHEN UPPER(accreditation_no) ~ '^[PH]91' THEN 'PRONCR NORTH'
               WHEN UPPER(accreditation_no) ~ '^[PH]92' THEN 'PRONCR SOUTH'
               WHEN UPPER(accreditation_no) ~ '^[PH]93' THEN 'PRONCR CENTRAL'
               ELSE UPPER(branch)
             END AS branch
      FROM users
      WHERE account_type = 'PHARMACY'
        AND status = 'APPROVED'
        AND NULLIF(accreditation_no, '') IS NOT NULL
    ) p
    WHERE v_caller.role = 'ADMIN' OR p.branch = UPPER(COALESCE(v_caller.branch, '__NONE__'))
    GROUP BY accreditation_no
  ) t;

  RETURN COALESCE(result, '[]'::json);
END;
$$;
