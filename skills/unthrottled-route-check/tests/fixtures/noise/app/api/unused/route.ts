import { Ratelimit } from "@upstash/ratelimit";
import OpenAI from "openai";
const ai = new OpenAI();
const rl = new Ratelimit({ redis: {} as any, limiter: Ratelimit.slidingWindow(10, "60 s") });
export async function POST() { return Response.json(await ai.responses.create({ model: "gpt-5-mini", input: "x" })); }
