# Upgrading kr

## Pods keep running while kr is replaced

From the first release that contains ADR-036, restarting `kr server` or `kr agent` does not stop
pods: each container has a small `kr shim` parent, the sandbox is its own process, and the new
process re-adopts them (IP, processes, open connections, exit status, terminal log).

Upgrade of a node that runs such a version:

1. Replace the binary (`install -m755 kr.new /usr/local/bin/kr`; the running processes keep the
   old file open, nothing breaks).
2. `systemctl restart kr-agent` (or `kr-server`). The unit must have `KillMode=process`
   (`tools/systemd/*.service`); with the default `control-group`, systemd kills the pods.
3. The log shows `kubelet: adopted N pods (M running containers) left by the previous run`.

Rolling back is the same procedure. The `.adopt` record format is versioned and only ever
extended (new trailing fields and new record kinds are ignored by older readers), so adjacent
versions read each other's records. Shims and `kr egress` helpers keep running the binary they were
started from until their container ends; they speak no protocol with the kubelet beyond a unix
socket that hands out one descriptor, so mixing versions is safe.

A server and an agent (or two servers) on the same `KR_ROOT` refuse to run at once
(`kubelet.lock`). Requirements: Linux 5.9 or newer (`close_range`); older kernels still work but
pods then die with the process (the log says so at start).

## The first upgrade onto such a version restarts the node's pods

Builds before ADR-036 start every container with `PDEATHSIG=SIGKILL` tied to the agent. That
flag is set inside the container's process and cannot be cleared from outside, so when the old
process exits the kernel kills its pods, and a new binary cannot save them. For that one upgrade:

1. `kubectl drain NODE --ignore-daemonsets --delete-emptydir-data` (workloads move or wait),
2. replace the binary and restart the service,
3. `kubectl uncordon NODE`.

Every later upgrade can skip the drain.

## What is not preserved

* A running `kubectl exec` / `attach` session ends with the old process (reconnect; `attach -i`
  to a container with stdin works again right away).
* Rootless nodes keep pods through the restart as well; their egress NAT runs as `kr egress`
  and the pod network namespace holder survives. If the namespace holder died, the pods that used
  it are killed and recreated.
