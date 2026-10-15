# GAMOT (EGOS) — Easy GAMOT Online Support

Single-file frontend (index.html: HTML/CSS/JS) + Supabase (project ukdiibumagfqngqkqmom).
Deployed on Netlify from GitHub (itnorthhelpdesk-a11y/gamot-online-support, branch main).

## Rules
- main is PRODUCTION. Never commit or push to main. Work on a feature branch only.
- NEVER put a secret/service_role key in the code. Only the publishable key is allowed in the frontend.
- The local page connects to the LIVE database. Use test records only; ask before any destructive operation.
- Roles and permissions are decided server-side (SQL functions, RLS), never trusted from the frontend.
- All credential changes must be logged to account_audit_trail via p_performed_by.
- Accreditation prefixes: P91/H91 = NORTH, P92/H92 = SOUTH, P93/H93 = CENTRAL.
- Username = PhilHealth PIN (pharmacy) or Employee ID No. (staff); UNIQUE at DB level.
- Make the smallest change that does the job. Show me the diff before I accept it.
- SQL changes: write them as separate .sql files and show me first. I run them manually in the Supabase SQL Editor. Do not run SQL yourself.