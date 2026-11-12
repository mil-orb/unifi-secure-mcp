import { readFileSync } from 'node:fs';
// Single source for the release version: package.json.
export const version = JSON.parse(
  readFileSync(new URL('../package.json', import.meta.url), 'utf8'),
).version;
