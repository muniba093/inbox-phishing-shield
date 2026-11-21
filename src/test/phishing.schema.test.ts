import { describe, expect, it } from "vitest";

import { PhishingInputSchema } from "@/lib/phishing.schema";

const validInput = { subject: "", sender: "", body: "x" };

describe("phishing analysis input limits", () => {
  it("accepts a 500-character subject and rejects 501 characters", () => {
    expect(PhishingInputSchema.safeParse({ ...validInput, subject: "s".repeat(500) }).success).toBe(true);
    expect(PhishingInputSchema.safeParse({ ...validInput, subject: "s".repeat(501) }).success).toBe(false);
  });

  it("accepts a 200-character sender and rejects 201 characters", () => {
    expect(PhishingInputSchema.safeParse({ ...validInput, sender: "a".repeat(200) }).success).toBe(true);
    expect(PhishingInputSchema.safeParse({ ...validInput, sender: "a".repeat(201) }).success).toBe(false);
  });

  it("requires an email body of 1 to 20,000 characters", () => {
    expect(PhishingInputSchema.safeParse({ ...validInput, body: "x" }).success).toBe(true);
    expect(PhishingInputSchema.safeParse({ ...validInput, body: "x".repeat(20000) }).success).toBe(true);
    expect(PhishingInputSchema.safeParse({ ...validInput, body: "" }).success).toBe(false);
    expect(PhishingInputSchema.safeParse({ ...validInput, body: "x".repeat(20001) }).success).toBe(false);
  });
});