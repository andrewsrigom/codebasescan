import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
export interface ProcessResult {
  code: number;
  stdout: string;
}
export type TrustedScannerBinary = 'semgrep' | 'gitleaks' | 'depcruise' | 'jscpd';

function scannerCommand(binary: TrustedScannerBinary, args: string[]) {
  if (binary === 'depcruise')
    return {
      executable: process.execPath,
      args: [
        fileURLToPath(
          new URL(
            '../../node_modules/dependency-cruiser/bin/dependency-cruise.mjs',
            import.meta.url,
          ),
        ),
        ...args,
      ],
    };
  if (binary === 'jscpd')
    return {
      executable: process.execPath,
      args: [
        fileURLToPath(new URL('../../node_modules/jscpd/run-jscpd.js', import.meta.url)),
        ...args,
      ],
    };
  return { executable: binary, args };
}

export async function runScannerProcess(
  binary: TrustedScannerBinary,
  args: string[],
  cwd: string,
  signal?: AbortSignal,
): Promise<ProcessResult> {
  return new Promise((resolve, reject) => {
    let output = '';
    let bytes = 0;
    let settled = false;
    const env: NodeJS.ProcessEnv = {
      NODE_ENV: process.env.NODE_ENV,
      PATH: process.env.PATH,
      SYSTEMROOT: process.env.SYSTEMROOT,
      HOME: cwd,
      USERPROFILE: cwd,
      TMPDIR: cwd,
      TMP: cwd,
      TEMP: cwd,
      SEMGREP_SEND_METRICS: 'off',
      SEMGREP_ENABLE_VERSION_CHECK: '0',
      NO_COLOR: '1',
      JSCPD_NO_TIPS: '1',
    };
    const command = scannerCommand(binary, args);
    const child = spawn(command.executable, command.args, {
      cwd,
      env,
      shell: false,
      windowsHide: true,
      detached: process.platform !== 'win32',
      stdio: ['ignore', 'pipe', 'ignore'],
    });
    const kill = () => {
      try {
        if (process.platform !== 'win32' && child.pid) process.kill(-child.pid, 'SIGKILL');
        else child.kill('SIGKILL');
      } catch {
        /* The process may have already exited. */
      }
    };
    const fail = (message: string) => {
      if (settled) return;
      settled = true;
      kill();
      clearTimeout(timer);
      signal?.removeEventListener('abort', abort);
      reject(new Error(message));
    };
    const abort = () => fail('Scanner cancelled.');
    const timer = setTimeout(() => fail('Scanner exceeded its 45-second budget.'), 45000);
    signal?.addEventListener('abort', abort, { once: true });
    if (signal?.aborted) abort();
    child.stdout.on('data', (chunk: Buffer) => {
      bytes += chunk.length;
      if (bytes > 4 * 1024 * 1024) {
        fail('Scanner output exceeded the 4 MB limit.');
        return;
      }
      output += chunk.toString('utf8');
    });
    child.on('error', () =>
      fail(`${binary} could not start. Install the trusted scanner binary separately.`),
    );
    child.on('close', (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      signal?.removeEventListener('abort', abort);
      if (code === null) reject(new Error('Scanner terminated without an exit code.'));
      else resolve({ code, stdout: output });
    });
  });
}
