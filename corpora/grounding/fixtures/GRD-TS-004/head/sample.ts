export interface UserConfig {
  retries: number;
  timeoutMs: number;
  debug?: boolean;
}

export type Status = 'idle' | 'running';
