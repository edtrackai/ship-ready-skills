import OpenAI from "openai";
const openaiClient = new OpenAI();
export async function POST() {
  return Response.json(await openaiClient.responses.create({ model: "gpt-5-mini", input: "hi" }));
}
