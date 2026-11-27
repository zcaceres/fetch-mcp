import { createDnsMock, type DnsMock } from '../src/integrations/dns/mock.ts';
import { createOriginMock, type OriginMock } from '../src/integrations/origin/mock.ts';

export type World = {
  readonly origin: OriginMock;
  readonly dns: DnsMock;
};

export const createWorld = (): World => ({
  origin: createOriginMock(),
  dns: createDnsMock(),
});
