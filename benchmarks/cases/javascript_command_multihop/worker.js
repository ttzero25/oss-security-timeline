import { exec } from "child_process";

export function execute(command) {
  return exec(command);
}
