export async function POST() {
  const r = await fetch("https://api.anthropic.com/v1/messages", { method: "POST", body: "{}" });
  return new Response(r.body);
}
