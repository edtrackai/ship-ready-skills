import Anthropic from "@anthropic-ai/sdk";
const anthropic = new Anthropic();
export const ask = (q: string) => anthropic.messages.create({ model: "claude-haiku-4-5", max_tokens: 100, messages: [{ role: "user", content: q }] });
