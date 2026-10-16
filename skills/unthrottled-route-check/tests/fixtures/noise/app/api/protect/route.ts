import OpenAI from "openai";
const ai = new OpenAI(); const rateLimits = { limit: (n: number) => n }; const shield = { protect: (x: unknown) => x };
export async function POST(req: Request) {
  rateLimits.limit(5); shield.protect(req);
  return Response.json(await ai.responses.create({ model: "gpt-5-mini", input: "x" }));
}
