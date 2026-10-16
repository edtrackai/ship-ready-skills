const ANTHROPIC_URL = 'https://api.anthropic.com/v1/messages';
export async function POST() {
  return fetch(ANTHROPIC_URL, { method: "POST", body: "{}" });
}
