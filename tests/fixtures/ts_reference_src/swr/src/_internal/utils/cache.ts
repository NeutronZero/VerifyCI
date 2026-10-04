import { isOnline, isVisible, initFocus, initReconnect } from './web-preset';
import { onErrorRetry, compareConfig } from './config';

export function revalidateAllKeys(keys: string[]): void {
  for (const k of keys) {
    if (isOnline()) {
      onErrorRetry(k);
    }
  }
}

export function initCache(provider: Map<string, any>): [Map<string, any>, () => void] {
  const focusDisposer = initFocus(() => {
    revalidateAllKeys([]);
  });
  const reconnectDisposer = initReconnect(() => {
    revalidateAllKeys([]);
  });
  const mutate = () => {
    provider.clear();
  };
  return [provider, mutate];
}

export function clearCache(provider: Map<string, any>): void {
  if (compareConfig("cache", "default")) {
    provider.clear();
  }
}
