import OpenAI from "openai";
const openai = new OpenAI();
export async function POST(req: Request) {
  const { message } = await req.json();
  const r = await openai.chat.completions.create({ model: "gpt-5-mini", messages: [{ role: "user", content: message }] });
  return Response.json(r);
}
