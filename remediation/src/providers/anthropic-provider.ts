/**
 * Anthropic provider adapter for remediation planning.
 * It translates the shared remediation prompt into Anthropic's Messages API.
 */
import { AiPlanningProvider } from "./types";
import { buildErrorMessage, createPrompt, mergeAiPlan, parseJsonObject } from "./shared";
import { RemediationContext, RemediationPlan } from "../types";

type AnthropicResponse = {
  content?: Array<{
    type?: string;
    text?: string;
  }>;
};

export function createAnthropicProvider(): AiPlanningProvider {
  return {
    name: "anthropic",
    getConfigurationStatus() {
      return process.env.ANTHROPIC_API_KEY
        ? { configured: true }
        : { configured: false, reason: "ANTHROPIC_API_KEY not set" };
    },
    async generatePlan(context: RemediationContext, fallbackPlan: RemediationPlan) {
      const apiKey = process.env.ANTHROPIC_API_KEY;
      const model = process.env.ANTHROPIC_MODEL || "claude-sonnet-4-20250514";

      if (!apiKey) {
        return null;
      }

      const prompt = createPrompt(context);
      const system = prompt.find((message) => message.role === "system")?.content || "";
      const userContent = prompt
        .filter((message) => message.role === "user")
        .map((message) => message.content)
        .join("\n\n");

      const response = await fetch("https://api.anthropic.com/v1/messages", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "x-api-key": apiKey,
          "anthropic-version": "2023-06-01"
        },
        body: JSON.stringify({
          model,
          max_tokens: 2000,
          temperature: 0.2,
          system,
          messages: [
            {
              role: "user",
              content: userContent
            }
          ]
        })
      });

      if (!response.ok) {
        throw new Error(await buildErrorMessage(response, "Anthropic"));
      }

      const payload = await response.json() as AnthropicResponse;
      const textBlock = payload.content?.find((block) => block.type === "text");
      const content = textBlock?.text;
      if (!content) {
        return null;
      }

      return mergeAiPlan(parseJsonObject(content), fallbackPlan, "anthropic");
    }
  };
}
