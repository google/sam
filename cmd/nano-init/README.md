# nano-init

`nano-init` is a minimal init system designed to run as PID 1 in a container, while transparently proxying HTTP/HTTPS traffic to a Unix Domain Socket (UDS).

## What it does

1.  **PID 1 Duties (Zombie Reaping):** It correctly handles `SIGCHLD` to reap any zombie child processes spawned during the container's lifecycle.
2.  **UDS to TCP Proxy:** It spins up a transparent TCP listener on a random localhost port and securely proxies all traffic over a given Unix Domain Socket.
3.  **Process Management:** It wraps your target application (e.g., an agent), automatically injecting the standard `HTTP_PROXY` and `HTTPS_PROXY` environment variables pointing to the dynamic TCP port it opened.
4.  **Signal Propagation:** It intercepts termination signals (`SIGINT`, `SIGTERM`, `SIGQUIT`) and gracefully propagates them to the child process group to orchestrate clean shutdowns.
5.  **Exit Code Passthrough:** When the target process exits, `nano-init` catches its exit code and exits with the same code.

## Why it is needed

Many applications and standard libraries lack native support for using a Unix Domain Socket as an HTTP/HTTPS proxy. By running `nano-init` as the entrypoint, the containerized application can simply use standard TCP-based `HTTP_PROXY` environment variables to securely route traffic out through the node's Unix Domain Socket, without needing any code modifications or complex network configurations.

### Architecture & Rationale

When deploying agent sandboxes, runtimes like gVisor, Kata Containers, or Docker with `network:none` are used to completely isolate the network namespace. In this isolated environment, we securely bind mount a Unix Domain Socket into the sandbox. `nano-init` then acts as the primary init process, forwarding all the agent's HTTP traffic to that bind-mounted socket.

This approach is highly opinionated by design:
* **Simplified Auth/Authz:** HTTP has a long, well-established list of mechanisms for authentication and authorization. Funneling traffic through an HTTP proxy simplifies how we assert identity and enforce access control for agents.
* **Scalability vs L3/L4:** Supporting arbitrary L3 or L4 protocols directly is complex and difficult to scale securely. By enforcing HTTP proxying at the boundary, we avoid building a custom L3/L4 stack and instead leverage our existing network architecture to provide a highly scalable authentication and authorization framework.
## Usage

```bash
./nano-init <uds-path> <cmd> [args...]
```

Example:

```bash
./nano-init /var/run/sam.sock ./my-agent --flag1 value
```
