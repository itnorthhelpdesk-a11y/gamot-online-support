import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

// BAGO: kasama na ang x-egos-session sa allowed headers (session token ng EGOS)
const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type, x-egos-session",
};

// BAGO: kapag "true" ang secret na ito, REQUIRED ang session token.
// Habang hindi pa naka-set, gumagana pa rin ang lumang index.html (walang token).
const REQUIRE_SESSION = Deno.env.get("EGOS_REQUIRE_SESSION") === "true";
const STAFF_ROLES = ["ADMIN", "BRANCH_ADMIN", "STAFF", "BAS"];

// BAGO: kunin ang naka-login na user mula sa session token (parehong rules ng _current_caller sa SQL)
async function getSessionUser(req: Request, supabaseAdmin: any) {
  const token = req.headers.get("x-egos-session") || "";
  if (!token) return { present: false, user: null };

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
    return { present: true, user: null };
  }

  const { data: user } = await supabaseAdmin
    .from("users")
    .select("id, username, role, branch, accreditation_no, account_type, facility, status")
    .eq("id", session.user_id)
    .maybeSingle();

  if (!user || user.status !== "APPROVED") return { present: true, user: null };

  await supabaseAdmin.from("sessions").update({ last_seen_at: new Date().toISOString() }).eq("token_hash", hash);
  return { present: true, user };
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    // BAGO: PhilHealth staff lang (naka-login) ang puwedeng gumamit ng AI Auto-fill
    const SUPABASE_SECRET_KEYS = JSON.parse(Deno.env.get("SUPABASE_SECRET_KEYS")!);
    const supabaseAdmin = createClient(
      Deno.env.get("SUPABASE_URL")!,
      SUPABASE_SECRET_KEYS["default"]
    );

    const session = await getSessionUser(req, supabaseAdmin);
    if ((session.present || REQUIRE_SESSION) && !session.user) {
      return new Response(JSON.stringify({ success: false, error: "SESSION_EXPIRED" }), {
        status: 401,
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }
    if (session.user && !STAFF_ROLES.includes(session.user.role)) {
      return new Response(JSON.stringify({ success: false, error: "NOT_AUTHORIZED" }), {
        status: 403,
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    const { images } = await req.json();

    if (!images || images.length === 0) {
      return new Response(JSON.stringify({ success: false, error: "No images provided." }), {
        status: 400,
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    const GEMINI_API_KEY = Deno.env.get("GEMINI_API_KEY");

    const schema = {
      type: "object",
      properties: {
        names_match: { type: "boolean", nullable: true },
        mismatch_note: { type: "string", nullable: true },
        gacn_no: { type: "string", nullable: true },
        gatn_no: { type: "string", nullable: true },
        facility: { type: "string", nullable: true },
        facility_accreditation_no: { type: "string", nullable: true },
        claimant_last_name: { type: "string", nullable: true },
        claimant_first_name: { type: "string", nullable: true },
        claimant_contact: { type: "string", nullable: true },
        claim_amount: { type: "string", nullable: true }
      }
    };

    const prompt = "You are reading PhilHealth GAMOT (Government Assistance for Medicines Outpatient) document(s) " +
      "(these could be a GAMOT Prescription, GAMOT Availment Slip, or similar claims documents). " +
      (images.length > 1
        ? "You are given TWO documents. FIRST, compare the patient/claimant/beneficiary name shown on BOTH documents. " +
          "Set 'names_match' to true only if the name on both documents clearly refers to the SAME person (minor spelling variations in formatting are OK, but different names are NOT a match). " +
          "If the names do NOT match, or if you cannot confidently read a name on either document, set 'names_match' to false, " +
          "explain briefly in 'mismatch_note', and set ALL OTHER fields to null — do not extract any other data in this case, since we cannot confirm the documents belong to the same claim. " +
          "If the names DO match, set 'names_match' to true, leave 'mismatch_note' null, and proceed to extract the fields below by cross-referencing both documents. "
        : "Only one document is provided; set 'names_match' to true and 'mismatch_note' to null, then extract the fields below. "
      ) +
      "Extract the following fields if clearly visible. If a field is not clearly visible or you are not confident, return null for that field instead of guessing. Do not invent data. " +
      "GACN is a batch number (often starts with letters+numbers). GATN is an individual transaction number. " +
      "Facility Accreditation No. usually starts with a letter (e.g. P) followed by digits. " +
      "IMPORTANT for claim_amount: only extract a value that is SPECIFICALLY labeled as 'Claim Amount' (or a clearly equivalent exact label) on the document. " +
      "Do NOT use other monetary figures such as unit price, medicine cost, total cost, or any unlabeled amount — if there is no field explicitly labeled as the claim amount, return null for claim_amount rather than guessing from another number.";

    const parts = [{ text: prompt }];
    images.forEach(function(img) {
      parts.push({ inline_data: { mime_type: img.mimeType, data: img.base64Image } });
    });

    const response = await fetch(
      "https://generativelanguage.googleapis.com/v1beta/models/gemini-3.8-flash:generateContent?key=" + GEMINI_API_KEY,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          contents: [{ parts: parts }],
          generationConfig: {
            responseMimeType: "application/json",
            responseSchema: schema
          }
        })
      }
    );

    const result = await response.json();

    if (!response.ok) {
      return new Response(JSON.stringify({ success: false, error: result.error?.message || "Gemini API error" }), {
        status: 500,
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    const extractedText = result.candidates?.[0]?.content?.parts?.[0]?.text;
    const extractedData = extractedText ? JSON.parse(extractedText) : {};

    return new Response(JSON.stringify({ success: true, data: extractedData }), {
      headers: { ...corsHeaders, "Content-Type": "application/json" }
    });
  } catch (e) {
    return new Response(JSON.stringify({ success: false, error: e.message }), {
      status: 500,
      headers: { ...corsHeaders, "Content-Type": "application/json" }
    });
  }
});
