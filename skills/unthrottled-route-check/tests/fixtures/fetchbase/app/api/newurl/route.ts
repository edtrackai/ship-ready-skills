const HOST = `https://api.openai.com`;
export async function POST() { return fetch(new URL("/v1/responses", HOST), { method: "POST" }); }
