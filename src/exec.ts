import { execFile } from 'node:child_process';

export interface ExecResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}

export function runCommand(cmd: string, args: string[], timeoutMs: number): Promise<ExecResult> {
  return new Promise((resolve, reject) => {
    execFile(
      cmd,
      args,
      { timeout: timeoutMs, maxBuffer: 10 * 1024 * 1024, windowsHide: true },
      (error, stdout, stderr) => {
        if (error && (error as NodeJS.ErrnoException).code === 'ENOENT') {
          reject(new Error(`${cmd} bulunamadı; kurulu ve PATH içinde olduğundan emin olun`));
          return;
        }
        if (error && typeof (error as { code?: unknown }).code === 'string') {
          reject(error);
          return;
        }
        const exitCode =
          error && typeof (error as { code?: unknown }).code === 'number'
            ? ((error as { code: number }).code ?? 1)
            : 0;
        resolve({ stdout: stdout.toString(), stderr: stderr.toString(), exitCode });
      },
    );
  });
}

export async function commandVersion(cmd: string): Promise<string> {
  const flags = [['--version'], ['-version'], ['-V']];
  for (const flag of flags) {
    try {
      const result = await runCommand(cmd, flag, 5000);
      const text = `${result.stdout}\n${result.stderr}`.trim();
      if (text) return text.split(/\r?\n/)[0]!.slice(0, 120);
    } catch {
      // sıradaki bayrağı dene
    }
  }
  return 'sürüm alınamadı';
}
