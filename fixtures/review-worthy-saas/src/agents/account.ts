import { createAgent } from 'langchain';
import { readUser, deleteUser, issueRefund } from '../tools/accounts';

export const accountAgent = createAgent({
  model: 'local-fixture-model',
  tools: [readUser, deleteUser, issueRefund],
});
