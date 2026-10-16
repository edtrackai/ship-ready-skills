import Stripe from "stripe";
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);
export async function POST() {
  const s = await stripe.checkout.sessions.create({ mode: "payment", line_items: [] });
  return Response.json({ url: s.url });
}
