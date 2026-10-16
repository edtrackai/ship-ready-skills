import OpenAI from "openai";
const llm = new OpenAI();
export async function POST() { return Response.json(await llm.chat.completions.create({ model: "gpt-5-mini", messages: [] })); }
