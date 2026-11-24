-- =====================================================================
-- EGOS: System Monitor (analytics para sa SYSTEM ADMIN lang)
-- Petsa: 2026-11-24
--
-- ANO ANG GINAGAWA:
--   Bagong function na get_system_analytics(). Isang tawag lang, ibinabalik
--   ang lahat ng kailangan ng system admin para ma-monitor ang 3 branch:
--     - per branch: accounts (approved/pending/declined/deactivated/locked),
--       registered pharmacies, online ngayon, active 7/30 araw, hindi pa
--       nakakapag-login, deficiency records, overdue RTF, refile na hindi pa
--       nare-review, average na tagal ng review, claim amounts
--     - "Most Active Branch": logins, ginawa sa system, refiles (30 araw)
--     - top 10 pinaka-aktibong users (30 araw)
--     - EGOS Impact Summary: users, claims handled/resolved/paid/open/denied
--       at halaga ng mga ito bawat branch
--     - Top 10 RTF reasons (issue category + specific issue) bawat branch
--     - araw-araw na logins (huling 30 araw), bagong registration (6 buwan)
--     - accounts per role, top 10 pharmacy na may pinakamaraming open record
--     - security: failed logins, locked accounts, pinakamaraming failed login
--     - email queue (MR notices), huling 15 account changes
--
-- SINO ANG PUWEDE: ADMIN lang (system admin). Ang server ang nagche-check
--   sa session token; BRANCH_ADMIN, STAFF, BAS at pharmacy ay NOT_AUTHORIZED.
--
-- READ-ONLY: walang binabago sa kahit anong table.
-- Patakbuhin ito BAGO i-deploy ang bagong index.html.
-- ROLLBACK: 2026-11-24_13_rollback.sql
-- =====================================================================

BEGIN;

CREATE OR REPLACE FUNCTION public.get_system_analytics()
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path = public, extensions
AS $function$
DECLARE
  v_caller public.users;
  v_branches JSON;
  v_top_users JSON;
  v_rtf_reasons JSON;
  v_logins_daily JSON;
  v_registrations JSON;
  v_roles JSON;
  v_top_pharmacies JSON;
  v_security JSON;
  v_top_failed JSON;
  v_email_queue JSON;
  v_recent_changes JSON;
BEGIN
  v_caller := _current_caller(ARRAY['ADMIN']);

  -- ---------- 1. PER BRANCH ----------
  WITH u AS (
    SELECT id, UPPER(username) AS username,
           COALESCE(NULLIF(UPPER(branch), ''), 'UNASSIGNED') AS branch,
           account_type, status, accreditation_no, locked_until, created_at
    FROM users
  ),
  last_login AS (
    SELECT UPPER(username) AS username, MAX(created_at) AS last_at
    FROM login_audit
    WHERE event = 'LOGIN_SUCCESS'
    GROUP BY UPPER(username)
  ),
  online AS (
    -- may buhay na session at may ginawa sa huling 30 minuto
    SELECT DISTINCT user_id
    FROM sessions
    WHERE revoked_at IS NULL AND expires_at > NOW() AND last_seen_at > NOW() - INTERVAL '30 minutes'
  ),
  acc AS (
    SELECT u.branch,
      COUNT(*) FILTER (WHERE u.status = 'APPROVED') AS users_approved,
      COUNT(*) FILTER (WHERE u.status = 'APPROVED' AND u.account_type = 'PHARMACY') AS pharmacy_users,
      COUNT(*) FILTER (WHERE u.status = 'APPROVED' AND u.account_type IS DISTINCT FROM 'PHARMACY') AS staff_users,
      COUNT(*) FILTER (WHERE u.status = 'PENDING') AS pending,
      COUNT(*) FILTER (WHERE u.status = 'REJECTED') AS rejected,
      COUNT(*) FILTER (WHERE u.status = 'DEACTIVATED') AS deactivated,
      COUNT(*) FILTER (WHERE u.locked_until > NOW()) AS locked_now,
      COUNT(DISTINCT u.accreditation_no) FILTER (
        WHERE u.status = 'APPROVED' AND u.account_type = 'PHARMACY' AND NULLIF(u.accreditation_no, '') IS NOT NULL
      ) AS pharmacies,
      COUNT(*) FILTER (WHERE o.user_id IS NOT NULL) AS online_now,
      COUNT(*) FILTER (WHERE u.status = 'APPROVED' AND ll.last_at > NOW() - INTERVAL '7 days') AS active_7d,
      COUNT(*) FILTER (WHERE u.status = 'APPROVED' AND ll.last_at > NOW() - INTERVAL '30 days') AS active_30d,
      COUNT(*) FILTER (WHERE u.status = 'APPROVED' AND ll.last_at IS NULL) AS never_logged_in,
      COUNT(*) FILTER (WHERE u.created_at > NOW() - INTERVAL '30 days') AS new_30d
    FROM u
    LEFT JOIN last_login ll ON ll.username = u.username
    LEFT JOIN online o ON o.user_id = u.id
    GROUP BY u.branch
  ),
  pharm AS (
    -- huling login ng kahit sinong account ng pharmacy
    SELECT u.branch, u.accreditation_no, MAX(ll.last_at) AS last_at
    FROM u
    LEFT JOIN last_login ll ON ll.username = u.username
    WHERE u.status = 'APPROVED' AND u.account_type = 'PHARMACY' AND NULLIF(u.accreditation_no, '') IS NOT NULL
    GROUP BY u.branch, u.accreditation_no
  ),
  pharm_b AS (
    SELECT branch,
      COUNT(*) FILTER (WHERE last_at > NOW() - INTERVAL '30 days') AS pharmacies_active_30d,
      COUNT(*) FILTER (WHERE last_at IS NULL OR last_at <= NOW() - INTERVAL '30 days') AS pharmacies_inactive_30d
    FROM pharm
    GROUP BY branch
  ),
  def AS (
    SELECT COALESCE(NULLIF(UPPER(pro_region), ''), 'UNASSIGNED') AS branch,
      COUNT(*) AS records_total,
      COUNT(*) FILTER (WHERE status IN ('RTF', 'REFILED', 'PROCESSING', 'FOR_MR')) AS records_open,
      COUNT(*) FILTER (WHERE status = 'RTF') AS rtf,
      COUNT(*) FILTER (WHERE status = 'REFILED') AS refiled,
      COUNT(*) FILTER (WHERE status = 'PROCESSING') AS processing,
      COUNT(*) FILTER (WHERE status = 'FOR_MR') AS for_mr,
      COUNT(*) FILTER (WHERE status = 'RESOLVED') AS resolved,
      COUNT(*) FILTER (WHERE status = 'DENIED') AS denied,
      COUNT(*) FILTER (WHERE status = 'RTF' AND compliance_deadline < NOW()) AS rtf_overdue,
      COUNT(*) FILTER (WHERE is_late_submission = true) AS late_submissions,
      COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '30 days') AS records_30d,
      COUNT(DISTINCT facility_accreditation_no) FILTER (
        WHERE status IN ('RTF', 'REFILED', 'PROCESSING', 'FOR_MR')
      ) AS pharmacies_with_open,
      COALESCE(SUM(claim_amount), 0) AS claim_total,
      COALESCE(SUM(claim_amount) FILTER (WHERE paid IS NOT TRUE), 0) AS claim_unpaid,
      -- para sa EGOS Impact Summary (halaga bawat yugto)
      COALESCE(SUM(claim_amount) FILTER (WHERE status = 'RESOLVED'), 0) AS claim_resolved,
      COUNT(*) FILTER (WHERE paid = true) AS paid_count,
      COALESCE(SUM(claim_amount) FILTER (WHERE paid = true), 0) AS claim_paid,
      COALESCE(SUM(claim_amount) FILTER (WHERE status IN ('RTF', 'REFILED', 'PROCESSING', 'FOR_MR')), 0) AS claim_open,
      COALESCE(SUM(claim_amount) FILTER (WHERE status = 'DENIED'), 0) AS claim_denied,
      ROUND((EXTRACT(EPOCH FROM AVG(resolved_timestamp - created_at)
        FILTER (WHERE status = 'RESOLVED' AND resolved_timestamp IS NOT NULL)) / 86400)::numeric, 1) AS avg_days_to_resolve
    FROM deficiency_records
    GROUP BY 1
  ),
  ref AS (
    SELECT COALESCE(NULLIF(UPPER(pro_region), ''), 'UNASSIGNED') AS branch,
      COUNT(*) FILTER (WHERE submitted_at > NOW() - INTERVAL '30 days') AS refiles_30d,
      COUNT(*) FILTER (WHERE review_result IS NULL) AS refile_pending_review,
      COUNT(*) FILTER (WHERE review_result IS NULL AND submitted_at < NOW() - INTERVAL '3 days') AS refile_waiting_3d,
      ROUND((EXTRACT(EPOCH FROM AVG(reviewed_at - submitted_at)
        FILTER (WHERE reviewed_at IS NOT NULL AND reviewed_at > NOW() - INTERVAL '30 days')) / 3600)::numeric, 1) AS avg_review_hours_30d
    FROM refile_submissions
    GROUP BY 1
  ),
  lg AS (
    -- kabuuang bilang ng logins (huling 30 araw)
    SELECT COALESCE(NULLIF(UPPER(u2.branch), ''), 'UNASSIGNED') AS branch, COUNT(*) AS logins_30d
    FROM login_audit la
    JOIN users u2 ON UPPER(u2.username) = UPPER(la.username)
    WHERE la.event = 'LOGIN_SUCCESS' AND la.created_at > NOW() - INTERVAL '30 days'
    GROUP BY 1
  ),
  act AS (
    -- bilang ng ginawa sa system (records + accounts), huling 30 araw
    SELECT COALESCE(NULLIF(UPPER(branch), ''), 'UNASSIGNED') AS branch, COUNT(*) AS actions_30d
    FROM (
      SELECT branch FROM audit_trail WHERE performed_at > NOW() - INTERVAL '30 days'
      UNION ALL
      SELECT branch FROM account_audit_trail WHERE performed_at > NOW() - INTERVAL '30 days'
    ) x
    GROUP BY 1
  ),
  b AS (
    SELECT branch FROM acc
    UNION SELECT branch FROM def
    UNION SELECT branch FROM ref
    UNION SELECT unnest(ARRAY['PRONCR NORTH', 'PRONCR SOUTH', 'PRONCR CENTRAL'])
  )
  SELECT json_agg(row_to_json(t) ORDER BY t.sort_order, t.branch) INTO v_branches
  FROM (
    SELECT b.branch,
      CASE b.branch WHEN 'PRONCR NORTH' THEN 1 WHEN 'PRONCR SOUTH' THEN 2 WHEN 'PRONCR CENTRAL' THEN 3 ELSE 9 END AS sort_order,
      COALESCE(acc.users_approved, 0) AS users_approved,
      COALESCE(acc.pharmacy_users, 0) AS pharmacy_users,
      COALESCE(acc.staff_users, 0) AS staff_users,
      COALESCE(acc.pending, 0) AS pending,
      COALESCE(acc.rejected, 0) AS rejected,
      COALESCE(acc.deactivated, 0) AS deactivated,
      COALESCE(acc.locked_now, 0) AS locked_now,
      COALESCE(acc.pharmacies, 0) AS pharmacies,
      COALESCE(pharm_b.pharmacies_active_30d, 0) AS pharmacies_active_30d,
      COALESCE(pharm_b.pharmacies_inactive_30d, 0) AS pharmacies_inactive_30d,
      COALESCE(acc.online_now, 0) AS online_now,
      COALESCE(acc.active_7d, 0) AS active_7d,
      COALESCE(acc.active_30d, 0) AS active_30d,
      COALESCE(acc.never_logged_in, 0) AS never_logged_in,
      COALESCE(acc.new_30d, 0) AS new_30d,
      COALESCE(def.records_total, 0) AS records_total,
      COALESCE(def.records_open, 0) AS records_open,
      COALESCE(def.rtf, 0) AS rtf,
      COALESCE(def.refiled, 0) AS refiled,
      COALESCE(def.processing, 0) AS processing,
      COALESCE(def.for_mr, 0) AS for_mr,
      COALESCE(def.resolved, 0) AS resolved,
      COALESCE(def.denied, 0) AS denied,
      COALESCE(def.rtf_overdue, 0) AS rtf_overdue,
      COALESCE(def.late_submissions, 0) AS late_submissions,
      COALESCE(def.records_30d, 0) AS records_30d,
      COALESCE(def.pharmacies_with_open, 0) AS pharmacies_with_open,
      COALESCE(def.claim_total, 0) AS claim_total,
      COALESCE(def.claim_unpaid, 0) AS claim_unpaid,
      COALESCE(def.claim_resolved, 0) AS claim_resolved,
      COALESCE(def.paid_count, 0) AS paid_count,
      COALESCE(def.claim_paid, 0) AS claim_paid,
      COALESCE(def.claim_open, 0) AS claim_open,
      COALESCE(def.claim_denied, 0) AS claim_denied,
      def.avg_days_to_resolve,
      COALESCE(lg.logins_30d, 0) AS logins_30d,
      COALESCE(act.actions_30d, 0) AS actions_30d,
      COALESCE(ref.refiles_30d, 0) AS refiles_30d,
      COALESCE(ref.refile_pending_review, 0) AS refile_pending_review,
      COALESCE(ref.refile_waiting_3d, 0) AS refile_waiting_3d,
      ref.avg_review_hours_30d
    FROM b
    LEFT JOIN acc ON acc.branch = b.branch
    LEFT JOIN pharm_b ON pharm_b.branch = b.branch
    LEFT JOIN def ON def.branch = b.branch
    LEFT JOIN ref ON ref.branch = b.branch
    LEFT JOIN lg ON lg.branch = b.branch
    LEFT JOIN act ON act.branch = b.branch
  ) t;

  -- ---------- 1b. TOP 10 PINAKA-AKTIBONG USERS (huling 30 araw) ----------
  SELECT json_agg(row_to_json(t) ORDER BY t.logins + t.actions DESC, t.last_login DESC NULLS LAST) INTO v_top_users
  FROM (
    SELECT u.username, u.facility, u.role, u.account_type,
           COALESCE(NULLIF(UPPER(u.branch), ''), 'UNASSIGNED') AS branch,
           COALESCE(l.logins, 0) AS logins,
           COALESCE(a.actions, 0) AS actions,
           l.last_login
    FROM users u
    LEFT JOIN (
      SELECT UPPER(username) AS un, COUNT(*) AS logins, MAX(created_at) AS last_login
      FROM login_audit
      WHERE event = 'LOGIN_SUCCESS' AND created_at > NOW() - INTERVAL '30 days'
      GROUP BY 1
    ) l ON l.un = UPPER(u.username)
    LEFT JOIN (
      SELECT UPPER(performed_by_username) AS un, COUNT(*) AS actions
      FROM (
        SELECT performed_by_username FROM audit_trail WHERE performed_at > NOW() - INTERVAL '30 days'
        UNION ALL
        SELECT performed_by_username FROM account_audit_trail WHERE performed_at > NOW() - INTERVAL '30 days'
      ) x
      WHERE performed_by_username IS NOT NULL
      GROUP BY 1
    ) a ON a.un = UPPER(u.username)
    WHERE COALESCE(l.logins, 0) + COALESCE(a.actions, 0) > 0
    ORDER BY COALESCE(l.logins, 0) + COALESCE(a.actions, 0) DESC, l.last_login DESC NULLS LAST
    LIMIT 10
  ) t;

  -- ---------- 1c. RTF REASONS bawat branch (lahat ng branch na nasa data; ang page ang kumukuha ng top 10) ----------
  SELECT json_agg(row_to_json(t) ORDER BY t.total DESC) INTO v_rtf_reasons
  FROM (
    SELECT COALESCE(NULLIF(issue_category, ''), 'UNSPECIFIED') AS issue_category,
           COALESCE(NULLIF(specific_issue, ''), 'UNSPECIFIED') AS specific_issue,
           COALESCE(NULLIF(UPPER(pro_region), ''), 'UNASSIGNED') AS branch,
           COUNT(*) AS total
    FROM deficiency_records
    GROUP BY 1, 2, 3
  ) t;

  -- ---------- 2. ARAW-ARAW NA LOGINS (huling 30 araw, oras ng Pilipinas) ----------
  SELECT json_agg(row_to_json(t) ORDER BY t.day, t.branch) INTO v_logins_daily
  FROM (
    SELECT to_char((la.created_at AT TIME ZONE 'Asia/Manila')::date, 'YYYY-MM-DD') AS day,
           COALESCE(NULLIF(UPPER(u.branch), ''), 'UNASSIGNED') AS branch,
           COUNT(DISTINCT UPPER(la.username)) AS users,
           COUNT(*) AS logins
    FROM login_audit la
    JOIN users u ON UPPER(u.username) = UPPER(la.username)
    WHERE la.event = 'LOGIN_SUCCESS'
      AND la.created_at > NOW() - INTERVAL '30 days'
    GROUP BY 1, 2
  ) t;

  -- ---------- 3. BAGONG REGISTRATION (huling 6 buwan) ----------
  SELECT json_agg(row_to_json(t) ORDER BY t.month, t.branch) INTO v_registrations
  FROM (
    SELECT to_char(date_trunc('month', created_at AT TIME ZONE 'Asia/Manila'), 'YYYY-MM') AS month,
           COALESCE(NULLIF(UPPER(branch), ''), 'UNASSIGNED') AS branch,
           COUNT(*) FILTER (WHERE account_type = 'PHARMACY') AS pharmacy,
           COUNT(*) FILTER (WHERE account_type IS DISTINCT FROM 'PHARMACY') AS staff
    FROM users
    WHERE created_at > date_trunc('month', NOW() AT TIME ZONE 'Asia/Manila') - INTERVAL '5 months'
    GROUP BY 1, 2
  ) t;

  -- ---------- 4. APPROVED ACCOUNTS PER ROLE ----------
  SELECT json_agg(row_to_json(t) ORDER BY t.total DESC) INTO v_roles
  FROM (
    SELECT COALESCE(role, 'NONE') AS role,
           COUNT(*) AS total,
           COUNT(*) FILTER (WHERE UPPER(branch) = 'PRONCR NORTH') AS north,
           COUNT(*) FILTER (WHERE UPPER(branch) = 'PRONCR SOUTH') AS south,
           COUNT(*) FILTER (WHERE UPPER(branch) = 'PRONCR CENTRAL') AS central
    FROM users
    WHERE status = 'APPROVED'
    GROUP BY 1
  ) t;

  -- ---------- 5. TOP 10 PHARMACY NA MAY PINAKAMARAMING OPEN RECORD ----------
  SELECT json_agg(row_to_json(t) ORDER BY t.open_records DESC, t.overdue DESC) INTO v_top_pharmacies
  FROM (
    SELECT d.facility_accreditation_no AS accreditation_no,
           -- pangalan: (1) mula sa registered account ng pharmacy; (2) pinakamadalas sa records,
           -- hindi kasama ang mga maling na-encode na GACN number; (3) accreditation no.
           COALESCE(
             (SELECT MAX(pu.facility) FROM users pu
               WHERE pu.account_type = 'PHARMACY' AND pu.status = 'APPROVED'
                 AND UPPER(pu.accreditation_no) = UPPER(d.facility_accreditation_no)),
             MODE() WITHIN GROUP (ORDER BY d.facility) FILTER (WHERE NULLIF(d.facility, '') IS NOT NULL AND d.facility !~* '^GACN'),
             d.facility_accreditation_no
           ) AS facility,
           MAX(UPPER(d.pro_region)) AS branch,
           COUNT(*) AS open_records,
           COUNT(*) FILTER (WHERE d.status = 'RTF' AND d.compliance_deadline < NOW()) AS overdue,
           (SELECT MAX(la.created_at)
              FROM login_audit la
              JOIN users pu ON UPPER(pu.username) = UPPER(la.username)
             WHERE la.event = 'LOGIN_SUCCESS'
               AND UPPER(pu.accreditation_no) = UPPER(d.facility_accreditation_no)) AS last_login
    FROM deficiency_records d
    WHERE d.status IN ('RTF', 'REFILED', 'PROCESSING', 'FOR_MR')
      AND NULLIF(d.facility_accreditation_no, '') IS NOT NULL
    GROUP BY d.facility_accreditation_no
    ORDER BY open_records DESC, overdue DESC
    LIMIT 10
  ) t;

  -- ---------- 6. SECURITY ----------
  SELECT json_build_object(
    'failed_24h', COUNT(*) FILTER (WHERE event = 'LOGIN_FAILED' AND created_at > NOW() - INTERVAL '24 hours'),
    'failed_7d',  COUNT(*) FILTER (WHERE event = 'LOGIN_FAILED' AND created_at > NOW() - INTERVAL '7 days'),
    'lockouts_7d', COUNT(*) FILTER (WHERE event = 'LOGIN_FAILED' AND details LIKE '%Account locked%' AND created_at > NOW() - INTERVAL '7 days'),
    'blocked_7d', COUNT(*) FILTER (WHERE event IN ('LOGIN_BLOCKED', 'LOGIN_LOCKED') AND created_at > NOW() - INTERVAL '7 days'),
    'logins_24h', COUNT(*) FILTER (WHERE event = 'LOGIN_SUCCESS' AND created_at > NOW() - INTERVAL '24 hours'),
    'locked_now', (SELECT COUNT(*) FROM users WHERE locked_until > NOW())
  ) INTO v_security
  FROM login_audit
  WHERE created_at > NOW() - INTERVAL '7 days';

  SELECT json_agg(row_to_json(t)) INTO v_top_failed
  FROM (
    SELECT la.username,
           MAX(UPPER(u.branch)) AS branch,
           (COUNT(u.id) = 0) AS unknown_user,
           COUNT(*) AS failed,
           MAX(la.created_at) AS last_attempt
    FROM login_audit la
    LEFT JOIN users u ON UPPER(u.username) = UPPER(la.username)
    WHERE la.event = 'LOGIN_FAILED' AND la.created_at > NOW() - INTERVAL '7 days'
    GROUP BY la.username
    ORDER BY failed DESC, last_attempt DESC
    LIMIT 8
  ) t;

  -- ---------- 7. EMAIL QUEUE (MR / Appeal notices) ----------
  SELECT json_build_object(
    'pending', COUNT(*) FILTER (WHERE status = 'PENDING'),
    'sent_30d', COUNT(*) FILTER (WHERE status = 'SENT' AND created_at > NOW() - INTERVAL '30 days'),
    'problem', COUNT(*) FILTER (WHERE status IN ('FAILED', 'PARTIAL', 'NO_RECIPIENT'))
  ) INTO v_email_queue
  FROM mr_notice_queue;

  -- ---------- 8. HULING 15 ACCOUNT CHANGES ----------
  SELECT json_agg(row_to_json(t) ORDER BY t.performed_at DESC) INTO v_recent_changes
  FROM (
    SELECT action, username_affected, performed_by_username, branch, performed_at
    FROM account_audit_trail
    ORDER BY performed_at DESC NULLS LAST
    LIMIT 15
  ) t;

  RETURN json_build_object(
    'generated_at', NOW(),
    'branches', COALESCE(v_branches, '[]'::json),
    'top_users', COALESCE(v_top_users, '[]'::json),
    'rtf_reasons', COALESCE(v_rtf_reasons, '[]'::json),
    'logins_daily', COALESCE(v_logins_daily, '[]'::json),
    'registrations', COALESCE(v_registrations, '[]'::json),
    'roles', COALESCE(v_roles, '[]'::json),
    'top_pharmacies', COALESCE(v_top_pharmacies, '[]'::json),
    'security', v_security,
    'top_failed', COALESCE(v_top_failed, '[]'::json),
    'email_queue', v_email_queue,
    'recent_changes', COALESCE(v_recent_changes, '[]'::json)
  );
END;
$function$;

COMMIT;
