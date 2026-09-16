import { execSync } from 'node:child_process';

export default async function stopSandbox({
  container_id,
}: {
  container_id: string;
}): Promise<void> {
  execSync(`docker rm -f ${container_id}`);
}
