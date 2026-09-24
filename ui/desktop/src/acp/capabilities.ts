import type { InitializeResponse } from '@agentclientprotocol/sdk';
import { getAcpInitializeResponse } from './acpConnection';

export interface AcpFeatureCapabilities {
  localInference: boolean;
  recipeParameterScopes: boolean;
}

export async function getAcpFeatureCapabilities(): Promise<AcpFeatureCapabilities> {
  const initializeResponse = await getAcpInitializeResponse();

  return {
    localInference: hasLocalInferenceCapability(initializeResponse),
    recipeParameterScopes: hasRecipeParameterScopesCapability(initializeResponse),
  };
}

export function hasLocalInferenceCapability(
  initializeResponse: Pick<InitializeResponse, 'agentCapabilities'>
): boolean {
  const agentCapabilities = initializeResponse.agentCapabilities;
  if (!agentCapabilities) {
    return false;
  }

  const meta = agentCapabilities._meta;
  if (!isRecord(meta)) {
    return false;
  }

  const warmachine = meta.warmachine;
  if (!isRecord(warmachine)) {
    return false;
  }

  return 'localInference' in warmachine;
}

export function hasRecipeParameterScopesCapability(
  initializeResponse: Pick<InitializeResponse, 'agentCapabilities'>
): boolean {
  const agentCapabilities = initializeResponse.agentCapabilities;
  if (!agentCapabilities) {
    return false;
  }

  const meta = agentCapabilities._meta;
  if (!isRecord(meta)) {
    return false;
  }

  const warmachine = meta.warmachine;
  if (!isRecord(warmachine)) {
    return false;
  }

  return 'recipeParameterScopes' in warmachine;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}
