/**
 * Provider registry for remediation planning.
 * This resolves the configured AI provider into the matching adapter.
 */
import { AiProvider } from "../types";
import { createAnthropicProvider } from "./anthropic-provider";
import { createGeminiProvider } from "./gemini-provider";
import { createOpenAiProvider } from "./openai-provider";
import { AiPlanningProvider } from "./types";

export function getConfiguredProviderName(): AiProvider {
  const rawValue = (process.env.AI_PROVIDER || "openai").trim().toLowerCase();
  if (rawValue === "anthropic" || rawValue === "gemini" || rawValue === "openai") {
    return rawValue;
  }
  return "openai";
}

export function createAiProvider(providerName: AiProvider): AiPlanningProvider {
  switch (providerName) {
    case "anthropic":
      return createAnthropicProvider();
    case "gemini":
      return createGeminiProvider();
    case "openai":
    default:
      return createOpenAiProvider();
  }
}
