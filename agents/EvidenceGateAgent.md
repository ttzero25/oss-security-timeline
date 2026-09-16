# EvidenceGateAgent

Input: a candidate trace, reachability result, normal/attack contrast evidence, and the collected public-advisory snapshot. Output: five explicit criteria and a `CONFIRMED`, `CONFIRMED_LOW`, `NEEDS_MORE_EVIDENCE`, or `REBUTTED` verdict.

The criteria cover external reachability, default configuration, attacker control, security impact, and known duplicates. A verdict controls only whether a private draft can be generated. External reporting and identifier requests remain manual.
