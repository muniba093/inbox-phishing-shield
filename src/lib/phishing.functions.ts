import { createServerFn } from "@tanstack/react-start";

import { requireSupabaseAuth } from "@/integrations/supabase/auth-middleware";
import {
  PhishingAnalysisSchema,
  PhishingInputSchema,
  type PhishingAnalysis,
} from "@/lib/phishing.schema";

const SYSTEM_PROMPT = `You are an expert cybersecurity AI specializing in phishing email detection.
Analyze the provided email and return ONLY a JSON response in this exact format:
{
  "verdict": "PHISHING" or "SAFE",
  "confidence": 87.5,
  "risk_level": "Critical" or "High" or "Medium" or "Low",
  "indicators": {
    "suspicious_links": true,
    "urgency_language": true,
    "sender_mismatch": false,
    "grammar_issues": false,
    "personal_info_request": true,
    "impersonation": true,
    "suspicious_attachments": false
  },
  "explanation": "2-3 sentence explanation of findings"
}
Return ONLY valid JSON, no extra text.`;

export const analyzeEmail = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((data: unknown) => PhishingInputSchema.parse(data))
  .handler(async ({ data }): Promise<PhishingAnalysis> => {
    const lovableApiKey = process.env["LOVABLE_API_KEY"];
    const connectionApiKey = process.env["UDC_GOOGLE_GEMINI_API_API_KEY"];
    if (!lovableApiKey || !connectionApiKey) {
      throw new Error("Gemini analysis is not configured yet.");
    }

    const userMessage = `Subject: ${data.subject}\nFrom: ${data.sender}\nBody:\n${data.body}`;
    const response = await fetch(
      "https://connector-gateway.lovable.dev/udc_google_gemini_api/v1beta/models/gemini-2.5-flash:generateContent",
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${lovableApiKey}`,
          "X-Connection-Api-Key": connectionApiKey,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          contents: [{ role: "user", parts: [{ text: `${SYSTEM_PROMPT}\n\n${userMessage}` }] }],
          generationConfig: { responseMimeType: "application/json" },
        }),
      },
    );

    if (!response.ok) {
      const errorBody = await response.text();
      console.error(`Gemini connector request failed [${response.status}]: ${errorBody}`);
      if (response.status === 429) {
        throw new Error("Gemini rate limit exceeded. Please try again shortly.");
      }
      throw new Error(`Gemini request failed [${response.status}]: ${errorBody}`);
    }

    const payload: unknown = await response.json();
    if (typeof payload !== "object" || payload === null || !("candidates" in payload)) {
      throw new Error("Gemini returned an invalid response. Please try again.");
    }
    const candidates = payload.candidates;
    if (!Array.isArray(candidates)) {
      throw new Error("Gemini returned an invalid response. Please try again.");
    }
    const firstCandidate = candidates[0];
    if (typeof firstCandidate !== "object" || firstCandidate === null || !("content" in firstCandidate)) {
      throw new Error("Gemini returned an invalid response. Please try again.");
    }
    const content = firstCandidate.content;
    if (typeof content !== "object" || content === null || !("parts" in content)) {
      throw new Error("Gemini returned an invalid response. Please try again.");
    }
    const parts = content.parts;
    if (!Array.isArray(parts)) {
      throw new Error("Gemini returned an invalid response. Please try again.");
    }
    const firstPart = parts[0];
    if (typeof firstPart !== "object" || firstPart === null || !("text" in firstPart)) {
      throw new Error("Gemini returned an invalid response. Please try again.");
    }
    const text = firstPart.text;
    if (typeof text !== "string") {
      throw new Error("Gemini returned an invalid response. Please try again.");
    }

    const cleaned = text.replace(/```json|```/g, "").trim();
    let parsed: unknown;
    try {
      parsed = JSON.parse(cleaned);
    } catch {
      throw new Error("Gemini returned an invalid response. Please try again.");
    }
    return PhishingAnalysisSchema.parse(parsed);
  });