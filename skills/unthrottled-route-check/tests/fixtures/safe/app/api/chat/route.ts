import OpenAI from "openai";
import { Ratelimit } from "@upstash/ratelimit";
import { Redis } from "@upstash/redis";
const rl = new Ratelimit({ redis: Redis.fromEnv(), limiter: Ratelimit.slidingWindow(10, "60 s") });
const openai = new OpenAI();
export async function POST(req: Request) {
  if (!(await rl.limit("u")).success) return new Response("slow down", { status: 429 });
  return Response.json(await openai.responses.create({ model: "gpt-5-mini", input: "hi" }));
}
