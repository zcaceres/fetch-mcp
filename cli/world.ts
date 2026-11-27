import { createDnsMock, type DnsMock } from '../src/integrations/dns/mock.ts';
import { createOriginMock, type OriginMock } from '../src/integrations/origin/mock.ts';
import { createYtDlpMock, type YtDlpMock } from '../src/integrations/ytdlp/mock.ts';

export type World = {
  readonly origin: OriginMock;
  readonly dns: DnsMock;
  readonly ytdlp: YtDlpMock;
  readonly env: Map<string, string>;
};

export const createWorld = (): World => ({
  origin: createOriginMock(),
  dns: createDnsMock(),
  ytdlp: createYtDlpMock(),
  env: new Map<string, string>(),
});
