import { execFileSync } from 'node:child_process';
import { win32 } from 'node:path';
import { fileURLToPath } from 'node:url';
// Windows PowerShell 5.1 lives under %SystemRoot%, which is not always C:\Windows.
// Read once; anything that is not a plain absolute drive path falls back to the default.
export function powershellPath(env = process.env) {
  const root = env.SystemRoot ?? env.SYSTEMROOT;
  const base =
    typeof root === 'string' && /^[a-z]:\\[^"*?<>|;]*$/i.test(root) && !root.includes('..')
      ? root
      : 'C:\\Windows';
  return win32.join(base, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
}
export const powershell = powershellPath();
// -ExecutionPolicy Bypass applies to this child process only; Group Policy still wins.
export const powershellArgs = (script, args = []) => [
  '-NoProfile',
  '-NonInteractive',
  '-ExecutionPolicy',
  'Bypass',
  '-File',
  fileURLToPath(new URL(`../scripts/${script}`, import.meta.url)),
  ...args,
];
// The bundled scripts exit 2 for failures they detect themselves. Any other failure
// means PowerShell could not run the script (execution policy, blocked download).
export function powershellError(error, failure, timeout = failure) {
  if (error?.code === 'ETIMEDOUT') return timeout;
  return error?.status === 2 ? failure : 'POWERSHELL_BLOCKED';
}
export function runPowerShell(script, args, options, failure, timeout) {
  try {
    return execFileSync(powershell, powershellArgs(script, args), {
      windowsHide: true,
      ...options,
    });
  } catch (error) {
    throw new Error(powershellError(error, failure, timeout));
  }
}
