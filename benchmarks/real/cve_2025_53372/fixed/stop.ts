import { execFileSync } from 'node:child_process';

export default async function stopSandbox({
  container_id,
}: {
  container_id: string;
}): Promise<void> {
  const validId = container_id.match(/^[a-zA-Z0-9_.-]+$/)?.[0];
  if (!validId) return;
  execFileSync('docker', ['rm', '-f', validId]);
}
