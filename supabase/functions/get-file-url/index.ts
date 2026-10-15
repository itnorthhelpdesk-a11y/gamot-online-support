import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

// Nagbibigay ng PANSAMANTALANG link (10 minuto) sa attachment, pero
// pagkatapos lang i-check na may karapatan ang naka-login na user.
//
//   refile-attachments  (corrected documents, MR letter)
//     - Pharmacy na may-ari (parehong accreditation no.)
//     - PhilHealth staff ng parehong branch; global ADMIN = lahat
//   registration-attachments  (dokumento sa pag-register)
//     - Global ADMIN; BRANCH_ADMIN ng parehong branch
//     - PHARMACY_ADMIN ng parehong accreditation no.
//     - Ang mismong nag-register
//
// Kailangan ang session token (header na x-egos-session). Naka-OFF dapat ang
// "Enforce JWT verification" sa dashboard (sariling session token ang gamit).

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type, x-egos-session",
};

const SIGNED_URL_SECONDS = 600;
const STAFF_ROLES = ["ADMIN", "BRANCH_ADMIN", "STAFF", "BAS"];
const ALLOWED_BUCKETS = ["refile-attachments", "registration-attachments"];

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });
}

// Parehong rules ng _current_caller sa SQL
async function getSessionUser(req: Request, supabaseAdmin: any) {
  const token = req.headers.get("x-egos-session") || "";
  if (!token) return null;

  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token));
  const hash = Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, "0")).join("");

  const { data: session } = await supabaseAdmin
    .from("sessions")
    .select("user_id, expires_at, last_seen_at, revoked_at")
    .eq("token_hash", hash)
    .maybeSingle();

  const now = Date.now();
  if (!session || session.revoked_at
      || new Date(session.expires_at).getTime() <= now
      || new Date(session.last_seen_at).getTime() <= now - 2 * 60 * 60 * 1000) {
    return null;
  }

  const { data: user } = await supabaseAdmin
    .from("users")
    .select("id, username, role, branch, accreditation_no, account_type, status")
    .eq("id", session.user_id)
    .maybeSingle();

  if (!user || user.status !== "APPROVED") return null;

  await supabaseAdmin.from("sessions").update({ last_seen_at: new Date().toISOString() }).eq("token_hash", hash);
  return user;
}

// ".../storage/v1/object/public/<bucket>/<path>" -> { bucket, path }
function parseStorageUrl(url: string) {
  const m = String(url || "").match(/\/storage\/v1\/object\/(?:public|sign)\/([^/]+)\/([^?]+)/);
  if (!m) return null;
  return { bucket: m[1], path: decodeURIComponent(m[2]) };
}

const same = (a: unknown, b: unknown) =>
  !!a && !!b && String(a).toUpperCase() === String(b).toUpperCase();

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    const SUPABASE_SECRET_KEYS = JSON.parse(Deno.env.get("SUPABASE_SECRET_KEYS")!);
    const supabaseAdmin = createClient(
      Deno.env.get("SUPABASE_URL")!,
      SUPABASE_SECRET_KEYS["default"]
    );

    const user = await getSessionUser(req, supabaseAdmin);
    if (!user) return json({ success: false, error: "SESSION_EXPIRED" }, 401);

    const { url } = await req.json();
    const parsed = parseStorageUrl(url);
    if (!parsed || !ALLOWED_BUCKETS.includes(parsed.bucket)) {
      return json({ success: false, error: "Invalid file link." }, 400);
    }

    const isStaff = STAFF_ROLES.includes(user.role) && user.account_type !== "PHARMACY";
    let allowed = false;

    if (parsed.bucket === "refile-attachments") {
      // Hanapin ang record na may-ari ng file (corrected document o MR letter)
      const findBy = async (column: string) => (await supabaseAdmin
        .from("deficiency_records")
        .select("gatn_no, pro_region, facility_accreditation_no")
        .eq(column, url)
        .limit(1)
        .maybeSingle()).data;
      const rec = (await findBy("refile_file_link")) || (await findBy("mr_letter_link"));

      if (rec) {
        if (user.account_type === "PHARMACY") {
          allowed = same(user.accreditation_no, rec.facility_accreditation_no);
        } else if (isStaff) {
          allowed = user.role === "ADMIN" || same(user.branch, rec.pro_region);
        }
      }
    } else {
      // Registration document: hanapin ang account na nag-upload nito
      const { data: owner } = await supabaseAdmin
        .from("users")
        .select("id, branch, accreditation_no")
        .eq("attachment_link", url)
        .limit(1)
        .maybeSingle();

      if (owner) {
        allowed = owner.id === user.id
          || user.role === "ADMIN"
          || (user.role === "BRANCH_ADMIN" && same(user.branch, owner.branch))
          || (user.role === "PHARMACY_ADMIN" && same(user.accreditation_no, owner.accreditation_no));
      }
    }

    if (!allowed) return json({ success: false, error: "You are not authorized to view this file." }, 403);

    const { data: signed, error: signError } = await supabaseAdmin.storage
      .from(parsed.bucket)
      .createSignedUrl(parsed.path, SIGNED_URL_SECONDS);

    if (signError || !signed?.signedUrl) {
      return json({ success: false, error: "File not found." }, 404);
    }

    return json({ success: true, url: signed.signedUrl });
  } catch (e) {
    return json({ success: false, error: e.message }, 500);
  }
});
