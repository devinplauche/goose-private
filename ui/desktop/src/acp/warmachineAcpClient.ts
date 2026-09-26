import {
  client,
  methods,
  type Client,
  type ClientConnection,
  type Stream,
} from '@agentclientprotocol/sdk';
import {
  WARMACHINE_EXT_AGENT_REQUESTS,
  WARMACHINE_EXT_NOTIFICATIONS,
  GooseExtClient,
  type GooseSessionNotification_unstable,
  type ProviderDeviceCodeNotification_unstable,
  type RecipeParamsResponse_unstable,
  type RequestRecipeParams_unstable,
  zGooseSessionNotification_unstable,
  zProviderDeviceCodeNotification_unstable,
  zRequestRecipeParams_unstable,
} from '@aaif/goose-acp-client';

const [gooseSessionUpdate, providerDeviceCode] = WARMACHINE_EXT_NOTIFICATIONS;
const [gooseRecipeParamsRequest] = WARMACHINE_EXT_AGENT_REQUESTS;

export type WarMachineAcpCallbacks = Required<
  Pick<Client, 'requestPermission' | 'sessionUpdate' | 'createElicitation'>
> & {
  unstable_sessionRecipeRequestParams: (
    request: RequestRecipeParams_unstable
  ) => Promise<RecipeParamsResponse_unstable>;
  unstable_sessionUpdate: (notification: GooseSessionNotification_unstable) => Promise<void>;
  unstable_providerDeviceCode: (
    notification: ProviderDeviceCodeNotification_unstable
  ) => Promise<void>;
};

export type WarMachineAcpClient = {
  connection: ClientConnection;
  warmachine: GooseExtClient;
};

export function connectWarMachineAcpClient(
  stream: Stream,
  callbacks: WarMachineAcpCallbacks
): WarMachineAcpClient {
  const app = client({ name: 'warmachine' })
    .onRequest(methods.client.session.requestPermission, (context) =>
      callbacks.requestPermission(context.params)
    )
    .onNotification(methods.client.session.update, (context) =>
      callbacks.sessionUpdate(context.params)
    )
    .onRequest(methods.client.elicitation.create, (context) =>
      callbacks.createElicitation(context.params)
    )
    .onRequest(gooseRecipeParamsRequest.method, zRequestRecipeParams_unstable, (context) =>
      callbacks.unstable_sessionRecipeRequestParams(context.params)
    )
    .onNotification(gooseSessionUpdate.method, zGooseSessionNotification_unstable, (context) =>
      callbacks.unstable_sessionUpdate(context.params)
    )
    .onNotification(
      providerDeviceCode.method,
      zProviderDeviceCodeNotification_unstable,
      (context) => callbacks.unstable_providerDeviceCode(context.params)
    );

  const connection = app.connect(stream);
  const warmachine = new GooseExtClient(connection.agent);

  return { connection, warmachine };
}
