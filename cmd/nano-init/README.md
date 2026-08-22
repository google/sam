# nano-init

PID 1 in an agent sandbox. It gives the sandbox one route, which leads to the
boundary, and then gets out of the agent's way.

## What it does

1. **Builds the only way out.** Creates `tun0` over netlink, gives it a
   link-local address, and makes it the default route. There is no other
   interface in the sandbox, so this is not the preferred path out; it is the
   only one.
2. **Carries a TCP stack.** Terminates the sandbox's TCP in userspace via
   gVisor (through `tun2socks`) and opens a SOCKS5 flow to the boundary for
   each connection.
3. **Keeps the name.** Answers DNS with a placeholder address per name and
   remembers the pairing, so what reaches the boundary is `mesh.sam.alt` rather
   than an address. The boundary chooses a provider from the name, which is the
   entire reason the name has to survive the trip.
4. **PID 1 duties.** Reaps orphans, propagates `SIGINT`/`SIGTERM`/`SIGQUIT` to
   the child's process group, and exits with the agent's own status.

It is a separate Go module. A userspace TCP stack is a large dependency and has
no business in the graph every other SAM binary builds from.

## What it deliberately does not do

It does not touch the agent. No `HTTP_PROXY` in its environment, no CA bundle
injected, nothing preloaded into its address space.

That is a reversal. This program used to do all three, and argued for it: route
everything through an HTTP proxy, the reasoning went, because HTTP has
well-established ways to assert identity, and supporting arbitrary L3/L4 would
mean building a network stack.

The objection is not that it was inelegant. It is that **every one of those
mechanisms is a request for the agent's cooperation.** `HTTP_PROXY` works if
the client library reads it. `LD_PRELOAD` works if the binary has a dynamic
loader. Both are outside the boundary the moment an agent uses a library that
ignores the convention, spawns a subprocess that clears its environment, or
speaks something that is not HTTP. An agent that has to cooperate with its own
confinement is not confined — and an agent driven by a model, acting on text it
did not write, is exactly the case where you cannot assume cooperation.

Routing does not ask. The cost is the network stack the old rationale wanted to
avoid, which is why this uses gVisor's rather than writing one: retransmission,
windowing and teardown are easy to get subtly wrong, and the symptom is tail
latency under load.

Name resolution is the one piece that looks like the old design and is not. The
resolver here is a convenience for clients that look a name up before
connecting; it is not a control. An agent that ignores it and hardcodes another
resolver has its packets routed through the tun regardless, and reaches exactly
what policy allows.

## Usage

```bash
nano-init run <boundary-socket> <cmd> [args...]
```

```bash
nano-init run /run/agent.sock python agent.py "summarise the open issues"
```

Needs `NET_ADMIN` and `/dev/net/tun` to build the tun. In a container:

```bash
docker run --rm --network none \
  --cap-add NET_ADMIN --device /dev/net/tun \
  -v /run/sam/agent.sock:/run/agent.sock \
  my-agent-image
```

`nano-init copy <dest>` writes the binary somewhere else, for building a sandbox
image that has nothing else in it.

## See also

- [Running agents on SAM](https://sam-mesh.dev/docs/user/running-agents/) — the
  full picture, including the microVM arrangement
- [Agent architecture](https://sam-mesh.dev/docs/agent-architecture/) — why the
  boundary speaks SOCKS5
