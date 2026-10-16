import Stripe from "stripe";
const stripe = new Stripe("sk_test_FAKE_FOR_TESTS");
const limiter = "TODO"; const msg = "throttle me";
export async function POST() { return Response.json(await stripe.checkout.sessions.create({ mode: "payment" })); }
