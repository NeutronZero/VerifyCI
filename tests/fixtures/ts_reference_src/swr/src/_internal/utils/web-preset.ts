let online = true;

export function isOnline(): boolean {
  return online;
}

export function isVisible(): boolean {
  return true;
}

export function initFocus(callback: () => void): () => void {
  const handler = () => callback();
  return handler;
}

export function initReconnect(callback: () => void): () => void {
  const handler = () => {
    online = true;
    callback();
  };
  return handler;
}

export const preset = {
  isOnline,
  isVisible,
};
