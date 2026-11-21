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

  it("accepts realistic synthetic profile details for assessment", () => {
    const suspiciousProfile = {
      ...validProfile,
      profileUrl: "https://social.example/harborbank-support",
      displayName: "Harbor Bank Account Help",
      username: "harborbank_secure_help",
      bio: "Official account recovery support. DM your password and verification code to restore access.",
      accountAge: "4 days",
      followers: "12",
      following: "4,830",
      additionalDetails: "The profile asks new followers to pay a small crypto fee to unlock their account.",
    };
    const ordinaryProfile = {
      ...validProfile,
      profileUrl: "https://social.example/elm-street-bakes",
      displayName: "Elm Street Bakes",
      username: "elmstreetbakes",
      bio: "Neighborhood bakery sharing today's menu and weekend opening hours.",
      accountAge: "5 years",
      followers: "1,860",
      following: "540",
      additionalDetails: "Posts show pastries, local events, and customer photos.",
    };

    expect(SocialProfileInputSchema.safeParse(suspiciousProfile).success).toBe(true);
    expect(SocialProfileInputSchema.safeParse(ordinaryProfile).success).toBe(true);
  });

  it("rejects missing identifiers and profile fields over their limits", () => {
    expect(SocialProfileInputSchema.safeParse({
      ...validProfile,
      profileUrl: " ",
      displayName: " ",
      username: " ",
    }).success).toBe(false);
    expect(SocialProfileInputSchema.safeParse({ ...validProfile, profileUrl: `https://social.example/${"a".repeat(500)}` }).success).toBe(false);
    expect(SocialProfileInputSchema.safeParse({ ...validProfile, bio: "b".repeat(3001) }).success).toBe(false);
  });
});

describe("website detector input", () => {
  it("accepts HTTP and HTTPS website addresses", () => {
    expect(WebsiteInputSchema.safeParse({ websiteUrl: "https://example.com", pageContent: "" }).success).toBe(true);
    expect(WebsiteInputSchema.safeParse({ websiteUrl: "http://example.com", pageContent: "" }).success).toBe(true);
  });

  it("accepts realistic synthetic suspicious and ordinary website details", () => {
    const suspiciousPage = {
      websiteUrl: "https://harborbank-secure.example/sign-in",
      pageContent: "Your account will be locked today. Enter your password, card number, and verification code to continue.",
    };
    const ordinaryPage = {
      websiteUrl: "https://help.example.com/account-security",
      pageContent: "We will never ask for your password or verification code. Sign in using the official app.",
    };

    expect(WebsiteInputSchema.safeParse(suspiciousPage).success).toBe(true);
    expect(WebsiteInputSchema.safeParse(ordinaryPage).success).toBe(true);
  });

  it("accepts a website URL at 2,048 characters and rejects one character over", () => {
    const atLimit = `https://example.com/${"a".repeat(2028)}`;
    const overLimit = `https://example.com/${"a".repeat(2029)}`;

    expect(atLimit).toHaveLength(2048);
    expect(WebsiteInputSchema.safeParse({ websiteUrl: atLimit, pageContent: "" }).success).toBe(true);
    expect(WebsiteInputSchema.safeParse({ websiteUrl: overLimit, pageContent: "" }).success).toBe(false);
  });

  it("rejects non-web protocols and page text over 10,000 characters", () => {
    expect(WebsiteInputSchema.safeParse({ websiteUrl: "ftp://example.com", pageContent: "" }).success).toBe(false);
    expect(WebsiteInputSchema.safeParse({ websiteUrl: "https://example.com", pageContent: "x".repeat(10001) }).success).toBe(false);
  });
});