import { initializeLucia } from "$lib/server/auth";
import { fail, redirect } from "@sveltejs/kit";

import type { Actions, PageServerLoad } from "./$types";

export const load: PageServerLoad = async ({ locals }) => {
  // ...
};

export const actions: Actions = {
  default: async (event) => {
    if (!event.locals.session) {
      return fail(401);
    }

    const lucia = initializeLucia(event.platform?.env.DB);
    await lucia.invalidateSession(event.locals.session.id);
    const sessionCookie = lucia.createBlankSessionCookie();
    event.cookies.set(sessionCookie.name, sessionCookie.value, {
      path: ".",
      ...sessionCookie.attributes,
    });
    redirect(302, "/login");
  },
};
