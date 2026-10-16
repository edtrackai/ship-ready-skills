import Stripe from "stripe";
import { limiter } from "../../../lib/rate-limit";
const stripe = new Stripe("sk_test_FAKE_FOR_TESTS");
export async function POST() {
  await limiter.limit("u");
  return Response.json(await stripe.checkout.sessions.create({ mode: "payment" }));
}
