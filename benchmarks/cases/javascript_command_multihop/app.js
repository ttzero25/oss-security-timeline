import { forward } from "./service.js";

export function route(req) {
  const command = req.body.command;
  return forward(command);
}
