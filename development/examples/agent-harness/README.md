# Agent harness

The canonical shape of an agent on SAM: about a hundred lines that hold the
conversation and the tool loop, and nothing else. No model endpoint to
configure, no API key, no tool servers deployed alongside it, and no network
beyond what its policy names.

Full walkthrough: [Running agents on SAM](https://sam-mesh.dev/docs/user/running-agents/).

## What it demonstrates

- **No credentials in the sandbox.** The gateway outside authenticates this
  agent to the mesh. There is no key in this directory, its environment, or the
  image built from it.
- **Services addressed by name.** `mesh.sam.alt` is not in DNS and has no route
  to it. The boundary resolves it and chooses a provider by policy, so the agent
  never learns where anything runs.
- **An ordinary HTTP client.** The OpenAI SDK and the MCP SDK, used as they
  would be anywhere. Nothing here is SAM-specific, because an agent that needed
  a special client could not be moved onto the mesh without rewriting it.

## Files

| | |
| --- | --- |
| `agent.py` | The harness. Discovers tools, calls a model, runs the loop. |
| `bundle.yaml` | Who this agent is and what it may reach. Read by `sam-box`, outside the sandbox. |
| `Dockerfile` | The sandbox image: the harness, plus `nano-init` to give it a route. |

The image contains no tun2proxy, no socat and no iproute2. `nano-init` carries
its own TCP stack and speaks netlink directly, so a sandbox can be the agent
and nothing else.

## Running it

With a `sam-node` already enrolled and serving its API on a socket:

```bash
# A boundary for this agent. Verification is on by default; the insecure flag
# is for local experiments and says what it costs: whoever can write the
# bundle decides which agent this sandbox is.
sam-box run \
  --socket /run/sam/agent.sock \
  --sidecar-socket /run/sam/node.sock \
  --bundle ./bundle.yaml \
  --insecure-unverified-bundle \
  --metrics-addr 127.0.0.1:9600

# The sandbox. --network none is the assertion, not just the arrangement:
# if this worked because the container could route somewhere, it would be
# proving nothing. NET_ADMIN and /dev/net/tun are needed to build the tun that
# becomes the only route out.
docker build -t agent-harness .
docker run --rm \
  --network none \
  --cap-add NET_ADMIN \
  --device /dev/net/tun \
  -v /run/sam/agent.sock:/run/agent.sock \
  agent-harness "What tools do I have, and what can each one do?"
```

Notice what is *not* passed: no API key, no mesh token, no proxy variable, no
endpoint. The agent asks for `mesh.sam.alt` and the sandbox has exactly one
route, which leads to the boundary.

## Seeing what it did

```bash
curl -s http://127.0.0.1:9600/metrics | grep sam_box_flows_total
```

Every flow the agent opened, by route class and outcome, including refusals.
A refused flow never becomes a latency, so counting is the only way to see it.
