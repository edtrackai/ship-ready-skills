import { notes } from "@/lib/ratelimit-docs/notes";
import OpenAI from "openai";
const ai = new OpenAI();
export async function POST() { return Response.json(await ai.responses.create({ model: "gpt-5-mini", input: notes })); }
