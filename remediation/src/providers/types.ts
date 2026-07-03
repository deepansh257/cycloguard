/**
 * Shared provider contracts for AI-backed remediation planning.
 * Each provider adapter implements the same interface so planner orchestration
 * stays independent from vendor-specific request/response details.
 */
import { AiProvider, RemediationContext, RemediationPlan } from "../types";

export type ProviderConfigStatus = {
  configured: boolean;
  reason?: string;
};

export type AiPlanningProvider = {
  name: AiProvider;
  getConfigurationStatus(): ProviderConfigStatus;
  generatePlan(context: RemediationContext, fallbackPlan: RemediationPlan): Promise<RemediationPlan | null>;
};
