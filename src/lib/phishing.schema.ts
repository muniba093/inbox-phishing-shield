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

export type PhishingInput = z.infer<typeof PhishingInputSchema>;
export type PhishingAnalysis = z.infer<typeof PhishingAnalysisSchema>;