/**
 * Gemini provider adapter for remediation planning.
 * It translates the shared remediation prompt into Gemini's generateContent API.
 */
import { AiPlanningProvider } from "./types";
import { buildErrorMessage, createPrompt, mergeAiPlan, parseJsonObject } from "./shared";
import { RemediationContext, RemediationPlan } from "../types";

type GeminiResponse = {
  candidates?: Array<{
    content?: {
      parts?: Array<{
        text?: string;
      }>;
    };
  }>;
};

export function createGeminiProvider(): AiPlanningProvider {
  return {
    name: "gemini",
    getConfigurationStatus() {
      return process.env.GEMINI_API_KEY
        ? { configured: true }
        : { configured: false, reason: "GEMINI_API_KEY not set" };
    },
    async generatePlan(context: RemediationContext, fallbackPlan: RemediationPlan) {
      const apiKey = process.env.GEMINI_API_KEY;
      const model = process.env.GEMINI_MODEL || "gemini-2.5-flash";

      if (!apiKey) {
        return null;
      }

      const prompt = createPrompt(context);
      const system = prompt.find((message) => message.role === "system")?.content || "";
      const userContent = prompt
        .filter((message) => message.role === "user")
        .map((message) => message.content)
        .join("\n\n");

      const response = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${encodeURIComponent(apiKey)}`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          systemInstruction: {
            parts: [{ text: system }]
          },
          contents: [
            {
              role: "user",
              parts: [{ text: userContent }]
            }
          ],
          generationConfig: {
            temperature: 0.2
          }
        })
      });

      if (!response.ok) {
        throw new Error(await buildErrorMessage(response, "Gemini"));
      }

      const payload = await response.json() as GeminiResponse;
      const content = payload.candidates?.[0]?.content?.parts
        ?.map((part) => part.text || "")
        .join("")
        .trim();

      if (!content) {
        return null;
      }

      return mergeAiPlan(parseJsonObject(content), fallbackPlan, "gemini");
    }
  };
}
