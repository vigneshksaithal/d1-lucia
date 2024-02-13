import { json, type RequestHandler } from "@sveltejs/kit";

export const GET: RequestHandler = async ({ params, platform }) => {
  const db = platform?.env.DB;
  const results = await db.prepare("SELECT * FROM user WHERE id = ?1", [
    "47h00akws3yf7pu",
  ]);

  return json({ results: results });
};
