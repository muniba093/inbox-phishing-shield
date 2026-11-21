import { describe, expect, it } from "vitest";

import {
  PhishingInputSchema,
  SocialProfileInputSchema,
  WebsiteInputSchema,
} from "@/lib/phishing.schema";

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

describe("social profile detector input", () => {
  const validProfile = {
    platform: "Instagram",
    profileUrl: "",
    displayName: "",
    username: "example",
    bio: "",
    accountAge: "",
    followers: "",
    following: "",
    additionalDetails: "",
  };

  it("requires a profile URL, username, or display name", () => {
    expect(SocialProfileInputSchema.safeParse(validProfile).success).toBe(true);
    expect(SocialProfileInputSchema.safeParse({ ...validProfile, username: "" }).success).toBe(false);
  });

  it("accepts only one of the supported social platforms", () => {
    expect(SocialProfileInputSchema.safeParse({ ...validProfile, platform: "X" }).success).toBe(true);
    expect(SocialProfileInputSchema.safeParse({ ...validProfile, platform: "Unknown Network" }).success).toBe(false);
  });
});

describe("website detector input", () => {
  it("accepts HTTP and HTTPS website addresses", () => {
    expect(WebsiteInputSchema.safeParse({ websiteUrl: "https://example.com", pageContent: "" }).success).toBe(true);
    expect(WebsiteInputSchema.safeParse({ websiteUrl: "http://example.com", pageContent: "" }).success).toBe(true);
  });

  it("rejects non-web protocols and page text over 10,000 characters", () => {
    expect(WebsiteInputSchema.safeParse({ websiteUrl: "ftp://example.com", pageContent: "" }).success).toBe(false);
    expect(WebsiteInputSchema.safeParse({ websiteUrl: "https://example.com", pageContent: "x".repeat(10001) }).success).toBe(false);
  });
});