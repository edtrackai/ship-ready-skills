import { Ratelimit } from "@upstash/ratelimit";
const rl = new Ratelimit({ redis: {} as any, limiter: Ratelimit.slidingWindow(60, "60 s") });
export async function middleware(req: Request) { await rl.limit("ip"); }
export const config = { matcher: ["/api/:path*"] };
