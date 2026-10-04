import { initCache, revalidateAllKeys, clearCache } from './_internal/utils/cache';
import { onErrorRetry, compareConfig, initDefaultConfig } from './_internal/utils/config';
import { isOnline, isVisible, initFocus, initReconnect } from './_internal/utils/web-preset';

export function useSWR(key: string): any {
  const [cache, mutate] = initCache(new Map());
  initDefaultConfig();
  initFocus(() => {});
  initReconnect(() => {});
  return { cache, mutate };
}

export function revalidate(key: string): void {
  revalidateAllKeys([key]);
}

export function subscribe(callback: () => void): boolean {
  if (isOnline()) {
    callback();
    return true;
  }
  return false;
}

export function checkVisibility(): boolean {
  return isVisible();
}

export function applyConfig(key: string): void {
  onErrorRetry(key);
  compareConfig(key, "standard");
}
