import { initializeLucia } from "$lib/server/auth";
import { fail, redirect } from "@sveltejs/kit";
import { Scrypt, generateId } from "lucia";

import type { Actions } from "./$types";

export const actions: Actions = {
  default: async ({ request, platform, cookies }) => {
    const formData = await request.formData();
    const username = formData.get("username");
    const password = formData.get("password");
    // username must be between 4 ~ 31 characters, and only consists of lowercase letters, 0-9, -, and _
    // keep in mind some database (e.g. mysql) are case insensitive
    if (
      typeof username !== "string" ||
      username.length < 3 ||
      username.length > 31 ||
      !/^[a-z0-9_-]+$/.test(username)
    ) {
      return fail(400, {
        message: "Invalid username",
      });
    }
    if (
      typeof password !== "string" ||
      password.length < 6 ||
      password.length > 255
    ) {
      return fail(400, {
        message: "Invalid password",
      });
    }

    const userId = generateId(15);
    const hashedPassword = await new Scrypt().hash(password);

    // TODO: check if username is already used

    const db = platform?.env.DB;
    const duration = await db
      .prepare(
        "INSERT INTO user (id, username, hashed_password) VALUES (?, ?, ?)",
      )
      .bind(userId, username, hashedPassword)
      .run();
    console.log(duration);

    const lucia = initializeLucia(db);

    const session = await lucia.createSession(userId, {});
    const sessionCookie = lucia.createSessionCookie(session.id);
    cookies.set(sessionCookie.name, sessionCookie.value, {
      path: ".",
      ...sessionCookie.attributes,
    });

    redirect(302, "/");
  },
};
