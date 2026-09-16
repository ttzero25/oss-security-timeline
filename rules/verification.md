# PoC verification rule

Use the unmodified checkout at the exact audited commit. The PoC must call the real application entry point, with a benign control and a crafted input run separately. Only an observable present in the crafted case and absent in the control satisfies the mechanical contrast check. A timeout, failed process or incomplete scaffold does not count as confirmation.

The default runner uses a fresh scratch directory, a reduced environment, timeout/output bounds, and additional operating-system resource limits on Linux. This local process mode does not fully prevent host file reads or network access. Use `--container` for a read-only repository mount and no network when the target or PoC needs stronger isolation. A matched marker is mechanical evidence; a reviewer must also verify that the marker came from the claimed security effect rather than from the harness itself.
