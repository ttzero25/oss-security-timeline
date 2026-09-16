import { execute } from "./worker.js";

export function forward(value) {
  return execute(value);
}
