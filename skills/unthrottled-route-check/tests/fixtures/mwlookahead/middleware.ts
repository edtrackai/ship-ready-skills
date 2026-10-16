import { Ratelimit } from "@upstash/ratelimit";
import { Redis } from "@upstash/redis";
const rl = new Ratelimit({ redis: Redis.fromEnv(), limiter: Ratelimit.slidingWindow(10, "60 s") });
export async function middleware(req: Request) { await rl.limit("ip"); }
export const config = { matcher: ["/((?!api|_next/static|_next/image|favicon.ico).*)"] };
