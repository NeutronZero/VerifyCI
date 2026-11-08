export interface UserConfig {
  retries: number;
  timeoutMs: number;
}

export type Status = 'idle' | 'running';
