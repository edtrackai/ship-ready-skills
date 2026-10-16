// TODO: add ratelimit here later
import { streamText } from "ai";
export async function POST() { return streamText({ model: "x", prompt: "hi" }).toTextStreamResponse(); }
