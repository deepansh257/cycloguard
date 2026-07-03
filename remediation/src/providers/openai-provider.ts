/**
 * OpenAI provider adapter for remediation planning.
 * This keeps OpenAI request formatting isolated from the planner core.
 */
import { AiPlanningProvider } from "./types";
import { buildErrorMessage, createPrompt, mergeAiPlan, parseJsonObject } from "./shared";
import { RemediationContext, RemediationPlan } from "../types";

type OpenAiResponse = {
  choices?: Array<{
    message?: {
      content?: string;
    };
  }>;
};

export function createOpenAiProvider(): AiPlanningProvider {
  return {
    name: "openai",
    getConfigurationStatus() {
      return process.env.OPENAI_API_KEY
        ? { configured: true }
        : { configured: false, reason: "OPENAI_API_KEY not set" };
    },
    async generatePlan(context: RemediationContext, fallbackPlan: RemediationPlan) {
      const apiKey = process.env.OPENAI_API_KEY;
      const model = process.env.OPENAI_MODEL || "gpt-4o-mini";

      if (!apiKey) {
        return null;
      }

      const response = await fetch("https://api.openai.com/v1/chat/completions", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${apiKey}`
        },
        body: JSON.stringify({
          model,
          temperature: 0.2,
          messages: createPrompt(context)
        })
      });

      if (!response.ok) {
        throw new Error(await buildErrorMessage(response, "OpenAI"));
      }

      const payload = await response.json() as OpenAiResponse;
      const content = payload.choices?.[0]?.message?.content;
      if (!content) {
        return null;
      }

      return mergeAiPlan(parseJsonObject(content), fallbackPlan, "openai");
    }
  };
}
