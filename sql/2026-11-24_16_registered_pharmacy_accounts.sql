-- =====================================================================
-- EGOS: Registered Pharmacies — bilang at listahan ng account bawat pharmacy
-- Petsa: 2026-11-24
--
-- ANO ANG BAGO: ang get_registered_pharmacies() ay nagbabalik na rin ng
--   - account_count : ilang APPROVED account ang naka-register sa pharmacy
--   - accounts      : listahan ng mga iyon (username, role, petsa ng
--                     registration, huling login). Walang password/email.
--
-- WALANG BINAGO SA ACCESS: ADMIN = lahat ng branch; BRANCH_ADMIN / STAFF /
--   BAS = sariling branch lang (pareho ng dati). Read-only ang function.
--
-- ROLLBACK: 2026-11-24_16_rollback.sql
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
    SELECT p.accreditation_no,
           MAX(p.facility) AS facility,
           MAX(p.branch) AS branch,
           COUNT(*) AS account_count,
           json_agg(json_build_object(
             'username',   p.username,
             'role',       p.role,
             'created_at', p.created_at,
             'last_login', ll.last_at
           ) ORDER BY (p.role = 'PHARMACY_ADMIN') DESC, p.username) AS accounts
    FROM (
      SELECT accreditation_no, facility, username, role, created_at,
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
    LEFT JOIN LATERAL (
      SELECT MAX(la.created_at) AS last_at
      FROM login_audit la
      WHERE UPPER(la.username) = UPPER(p.username)
        AND la.event = 'LOGIN_SUCCESS'
    ) ll ON TRUE
    WHERE v_caller.role = 'ADMIN' OR p.branch = UPPER(COALESCE(v_caller.branch, '__NONE__'))
    GROUP BY p.accreditation_no
  ) t;

  RETURN COALESCE(result, '[]'::json);
END;
$$;
