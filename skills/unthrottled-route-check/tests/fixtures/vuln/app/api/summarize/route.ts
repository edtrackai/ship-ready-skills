import { ask } from "@/lib/ai";
export async function POST(req: Request) { return Response.json(await ask(await req.text())); }
