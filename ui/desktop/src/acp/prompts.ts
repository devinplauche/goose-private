import type {
  GetPromptResponse_unstable,
  PromptTemplateEntry,
} from '@aaif/goose-acp-client';
import { getAcpClient } from './acpConnection';

export type PromptTemplate = PromptTemplateEntry;
export type PromptContent = GetPromptResponse_unstable;

export async function acpListPrompts(): Promise<PromptTemplate[]> {
  const client = await getAcpClient();
  const response = await client.warmachine.configPromptsList_unstable({});
  return response.prompts;
}

export async function acpGetPrompt(name: string): Promise<PromptContent> {
  const client = await getAcpClient();
  return client.warmachine.configPromptsGet_unstable({ name });
}

export async function acpSavePrompt(name: string, content: string): Promise<void> {
  const client = await getAcpClient();
  await client.warmachine.configPromptsSave_unstable({ name, content });
}

export async function acpResetPrompt(name: string): Promise<void> {
  const client = await getAcpClient();
  await client.warmachine.configPromptsReset_unstable({ name });
}
