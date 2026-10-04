import { optionsToUrl, urlToOptions, validateOptions, normalizeArguments } from './utils/options.js';

export function request(url, options) {
  validateOptions(options);
  const opts = urlToOptions(url);
  const formatted = optionsToUrl(opts);
  return { url: formatted, options: opts };
}

export function paginate(url, options) {
  const norm = normalizeArguments(options, {});
  return [norm];
}

export function asPromise(options) {
  const target = optionsToUrl(options);
  return Promise.resolve(target);
}
