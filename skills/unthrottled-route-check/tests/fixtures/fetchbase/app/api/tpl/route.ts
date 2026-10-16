const OPENAI_BASE = "https://api.openai.com/v1";
export async function POST() {
  const r = await fetch(`${OPENAI_BASE}/chat/completions`, { method: "POST", body: "{}" });
  return new Response(r.body);
}
