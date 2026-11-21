import { describe, expect, it } from "vitest";

import { PasswordSchema } from "@/lib/auth.schema";

describe("password setup", () => {
  it("requires at least 6 characters", () => {
    expect(PasswordSchema.safeParse("123456").success).toBe(true);
    expect(PasswordSchema.safeParse("12345").success).toBe(false);
  });
});