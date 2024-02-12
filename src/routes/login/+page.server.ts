import type { Actions, PageServerLoad } from "./$types";
import { fail, redirect } from "@sveltejs/kit";

export const load: PageServerLoad = async (event) => {
  if (!event.locals.user) redirect(302, "/login");
  return {
    username: event.locals.user.username,
  };
};
