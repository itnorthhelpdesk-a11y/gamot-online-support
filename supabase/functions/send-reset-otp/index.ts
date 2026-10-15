import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    const { username } = await req.json();

    const SUPABASE_SECRET_KEYS = JSON.parse(Deno.env.get("SUPABASE_SECRET_KEYS")!);
    const supabaseAdmin = createClient(
      Deno.env.get("SUPABASE_URL")!,
      SUPABASE_SECRET_KEYS["default"]
    );

    const { data: user, error: fetchError } = await supabaseAdmin
      .from("users")
      .select("email")
      .eq("username", username.toUpperCase())
      .single();

    if (fetchError || !user || !user.email) {
      return new Response(JSON.stringify({ success: false, error: "Account not found or has no email on file." }), {
        status: 400,
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    // Rate limiting — huwag payagan kung may request pa lang sa loob ng 2 minuto
    const twoMinutesAgo = new Date(Date.now() - 2 * 60 * 1000).toISOString();
    const { data: recentRequests } = await supabaseAdmin
      .from("password_reset_requests")
      .select("id")
      .eq("username", username.toUpperCase())
      .gte("created_at", twoMinutesAgo);

    if (recentRequests && recentRequests.length > 0) {
      return new Response(JSON.stringify({ success: false, error: "Please wait a couple of minutes before requesting another code." }), {
        status: 429,
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    // Daily cap — max 5 requests kada araw
    const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
    const { data: dailyRequests } = await supabaseAdmin
      .from("password_reset_requests")
      .select("id")
      .eq("username", username.toUpperCase())
      .gte("created_at", oneDayAgo);

    if (dailyRequests && dailyRequests.length >= 5) {
      return new Response(JSON.stringify({ success: false, error: "Too many reset code requests today. Please try again tomorrow or contact your admin." }), {
        status: 429,
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    // BAGO: cryptographically secure na random (dati Math.random)
    const otp = (100000 + (crypto.getRandomValues(new Uint32Array(1))[0] % 900000)).toString();
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString();

    await supabaseAdmin.from("password_reset_requests").insert({
      username: username.toUpperCase(),
      otp: otp,
      expires_at: expiresAt
    });

    const subject = "GAMOT Password Reset Code";
    const body = `Hi ${username},\n\nYour password reset code is: ${otp}\n\n` +
                 `This code will expire in 15 minutes. If you did not request this, please ignore this email.\n\n` +
                 `Thank you,\nEasy GAMOT Online Support Team`;

    const sendResult = await sendEmailWithFallback(user.email, subject, body);

    return new Response(JSON.stringify({ success: sendResult.success, error: sendResult.error }), {
      headers: { ...corsHeaders, "Content-Type": "application/json" }
    });
  } catch (e) {
    return new Response(JSON.stringify({ success: false, error: e.message }), {
      status: 500,
      headers: { ...corsHeaders, "Content-Type": "application/json" }
    });
  }
});

const GMAIL_SCRIPT_URL = "https://script.google.com/macros/s/AKfycbzI96QehmDTjIO54SpQrtPxOdyODxj9feCSwmALqCTXfk6PiVdGCLapiC_VCiomC_HnZg/exec";

async function sendEmailWithFallback(to: string, subject: string, text: string) {
  try {
    const res = await fetch(GMAIL_SCRIPT_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ to, subject, body: text })
    });
    const result = await res.json();
    if (result.success) return { success: true, method: "GMAIL" };
  } catch (e) {}

  try {
    const res = await fetch("https://api.brevo.com/v3/smtp/email", {
      method: "POST",
      headers: {
        "api-key": Deno.env.get("BREVO_API_KEY")!,
        "Content-Type": "application/json",
        "accept": "application/json"
      },
      body: JSON.stringify({
        sender: { name: "EYOS Support Team", email: "itnorthhelpdesk@gmail.com" },
        to: [{ email: to }],
        subject,
        textContent: text
      })
    });
    if (res.ok) return { success: true, method: "BREVO" };
    return { success: false, error: await res.text() };
  } catch (e) {
    return { success: false, error: e.message };
  }
}
