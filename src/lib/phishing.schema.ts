import { z } from "zod";

export const PhishingInputSchema = z.object({
  subject: z.string().max(500),
  sender: z.string().max(200),
  body: z.string().min(1).max(20000),
});

export const PhishingAnalysisSchema = z.object({
  verdict: z.enum(["PHISHING", "SAFE"]),
  confidence: z.number().min(0).max(100),
  risk_level: z.enum(["Critical", "High", "Medium", "Low"]),
  indicators: z.object({
    suspicious_links: z.boolean(),
    urgency_language: z.boolean(),
    sender_mismatch: z.boolean(),
    grammar_issues: z.boolean(),
    personal_info_request: z.boolean(),
    impersonation: z.boolean(),
    suspicious_attachments: z.boolean(),
  }),
  explanation: z.string().min(1),
});

export const SocialProfileInputSchema = z.object({
  platform: z.enum(["Instagram", "Facebook", "TikTok", "X", "LinkedIn", "Other"]),
  profileUrl: z.string().max(500),
  displayName: z.string().max(150),
  username: z.string().max(100),
  bio: z.string().max(3000),
  accountAge: z.string().max(80),
  followers: z.string().max(40),
  following: z.string().max(40),
  additionalDetails: z.string().max(3000),
}).refine(
  (input) => Boolean(input.profileUrl.trim() || input.username.trim() || input.displayName.trim()),
  { message: "Add a profile URL, username, or display name to continue." },
);

export const WebsiteInputSchema = z.object({
  websiteUrl: z.string().trim().max(2048).url().refine(
    (value) => /^https?:\/\//i.test(value),
    "Enter a website address that starts with http:// or https://.",
  ),
  pageContent: z.string().max(10000),
});

const DetectionSummarySchema = z.object({
  verdict: z.enum(["SUSPICIOUS", "NO_STRONG_SIGNALS"]),
  confidence: z.number().min(0).max(100),
  risk_level: z.enum(["Critical", "High", "Medium", "Low"]),
  explanation: z.string().min(1),
});

export const SocialProfileAnalysisSchema = DetectionSummarySchema.extend({
  indicators: z.object({
    impersonation_signals: z.boolean(),
    suspicious_links: z.boolean(),
    unusual_contact_requests: z.boolean(),
    engagement_mismatch: z.boolean(),
    incomplete_evidence: z.boolean(),
  }),
});

export const WebsiteAnalysisSchema = DetectionSummarySchema.extend({
  indicators: z.object({
    lookalike_domain: z.boolean(),
    suspicious_url_pattern: z.boolean(),
    insecure_http: z.boolean(),
    credential_or_payment_request: z.boolean(),
    brand_mismatch: z.boolean(),
    incomplete_evidence: z.boolean(),
  }),
});

export type PhishingInput = z.infer<typeof PhishingInputSchema>;
export type PhishingAnalysis = z.infer<typeof PhishingAnalysisSchema>;
export type SocialProfileInput = z.infer<typeof SocialProfileInputSchema>;
export type WebsiteInput = z.infer<typeof WebsiteInputSchema>;
export type SocialProfileAnalysis = z.infer<typeof SocialProfileAnalysisSchema>;
export type WebsiteAnalysis = z.infer<typeof WebsiteAnalysisSchema>;