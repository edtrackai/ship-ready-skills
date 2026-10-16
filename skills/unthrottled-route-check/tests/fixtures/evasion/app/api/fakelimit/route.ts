import { createClient } from "@supabase/supabase-js";
import OpenAI from "openai";
const db = createClient("u", "k");
const ai = new OpenAI();
export async function POST() {
  const { data } = await db.from("notes").select("*").limit(10);
  return Response.json(await ai.chat.completions.create({ model: "gpt-5-mini", messages: [{ role: "user", content: JSON.stringify(data) }] }));
}
