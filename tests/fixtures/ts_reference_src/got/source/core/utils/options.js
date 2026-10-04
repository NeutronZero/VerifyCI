export function optionsToUrl(options) {
  const protocol = options.protocol || 'https:';
  const host = options.host || 'localhost';
  return `${protocol}//${host}${options.path || '/'}`;
}

export function urlToOptions(url) {
  const parsed = new URL(url);
  return {
    protocol: parsed.protocol,
    host: parsed.host,
    hostname: parsed.hostname,
    pathname: parsed.pathname,
  };
}

export function validateOptions(options) {
  if (!options) {
    throw new Error('options required');
  }
  return true;
}

export function normalizeArguments(options, defaults) {
  return Object.assign({}, defaults, options);
}
