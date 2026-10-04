import { initCache, revalidateAllKeys } from './cache';
import { isOnline } from './web-preset';

export function onErrorRetry(key: string): void {
  if (isOnline()) {
    console.log("retrying", key);
  }
}

export function compareConfig(a: string, b: string): boolean {
  return a === b;
}

export function initDefaultConfig(): [Map<string, any>, () => void] {
  return initCache(new Map());
}

export function mergeConfigs(a: any, b: any): any {
  revalidateAllKeys(["default"]);
  return Object.assign({}, a, b);
}

export const defaultConfig = {
  compare: compareConfig,
};
