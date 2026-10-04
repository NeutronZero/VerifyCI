import { useSWR, revalidate, subscribe, checkVisibility, applyConfig } from './use-swr';
import { initCache } from './_internal/utils/cache';
import { compareConfig } from './_internal/utils/config';
import { initFocus, initReconnect } from './_internal/utils/web-preset';

export function useSWRHandler(key: string): any {
  return useSWR(key);
}

export function createSWRHook(): any {
  const [c, m] = initCache(new Map());
  return { c, m };
}

export function getDefaults(key: string): boolean {
  return compareConfig(key, "standard");
}

export function setupClient(cb: () => void): () => void {
  return initFocus(cb);
}

export function setupNetwork(cb: () => void): () => void {
  return initReconnect(cb);
}

export default useSWR;
