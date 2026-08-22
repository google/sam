---
title: "Scale Experiment Guide"
description: "How to reproduce the thousand-agent Firecracker run on GCP"
weight: 100
---

## Overview

This is the operational companion to
[Scale: what an agent costs]({{< relref "/docs/scale-report" >}}). The report says
what was measured and what it means; this says how to run it again.

The arrangement is one host, one `sam-node`, and *N* agents. Each agent is a
Firecracker microVM with **no network device at all** — no NIC, no bridge, no
route anywhere. Its only way out is a vsock to its own `sam-box`, which resolves
mesh names and applies policy to every flow. A thousand of these have been run
on a single `n2-standard-64`.

### Components

| | |
| --- | --- |
| **Host VM** | `n2-standard-64` on GCP with nested virtualisation, running the node and one `sam-box` per agent |
| **Guest** | Firecracker microVM, Alpine, ~160 MiB, no network device |
| **`nano-init`** | PID 1 in the guest: builds `tun0`, carries its own TCP stack, and restores the mesh name when it opens a flow |
| **Agent** | The [canonical harness](https://github.com/google/sam/tree/main/development/examples/agent-harness), holding no credentials |

`nano-init` speaks netlink directly and carries its own TCP stack, so the guest
needs no proxy configuration, no helper binaries and nothing fetched at build
time.

## Prerequisites

- A guest kernel built with `CONFIG_TUN=y`. The quickstart, 5.10 and 6.1
  Firecracker CI kernels **do not** have it; 6.18.41 does. `startup-script.sh`
  downloads a TUN-capable kernel and fails loudly rather than booting a guest
  whose agent can never get a route.
- A bootstrap token at `/etc/sam-bootstrap-token` on the host. The launcher
  refuses to start without one, rather than discovering the problem a thousand
  sandboxes later.
- KVM, with `/dev/kvm` writable by the invoking user.

## Step 1: build the guest image

Built once, locally, and uploaded — not rebuilt on every host.

```bash
# Alpine, python, nano-init and the agent, as an ext4 image
./scripts/build-rootfs.sh gs://my-sam-bucket/scale-test
```

The image ships the canonical harness rather than the chaos agent, deliberately:
a scale run wants the same request every time, and the chaos agent never issues
the same request twice.

To build a different agent in, point `AGENT_SRC` at it and give it room. The
size matters — an image that is too small fails during the copy, not at boot:

```bash
# The LangChain chaos agent needs roughly four times the harness's space
ROOTFS_MB=2048 AGENT_SRC=cmd/chaos-agent ./scripts/build-rootfs.sh
```

---

## Step 2: provision the host

```bash
./scripts/provision-scale-vm.sh \
  --prefix sam-minions --count 1 \
  --machine-type n2-standard-64 \
  --local-binaries gs://my-sam-bucket/scale-test \
  --no-spot
```

The script builds your local Go binaries and injects them alongside a
`startup-script.sh` that pulls everything down on boot.

Use `--no-spot` for anything you intend to keep. Spot capacity for this machine
type is thin, and a run reclaimed halfway through produces no result while
costing the same as one that finished. Standard instances also live-migrate
through host maintenance; spot ones are terminated by it, so a soak on spot is a
soak with a deadline somebody else sets.

If provisioning reports `ZONE_RESOURCE_POOL_EXHAUSTED`, try another zone.

---

## Step 3: size the guest

Once per agent image. An undersized guest fails in ways that look like network
faults, and an oversized one wastes the memory that decides the population
ceiling.

```bash
sudo tests/scale/measure-guest.sh
```

For the harness this found 136 MiB fails, 144 MiB runs slowly, and **160 MiB
runs at full speed**, against a working set of about 206 MiB.

---

## Step 4: launch the fleet

The host's `startup-script.sh` has already verified nested virtualisation,
downloaded Firecracker and a TUN-capable kernel, and pulled down the rootfs and
your `sam-node` / `sam-box` binaries.

```bash
gcloud compute ssh sam-minions-1 --zone us-central1-c

# Prove the launcher works before asking it for a thousand of anything
sudo tests/scale/validate-launcher.sh

sudo SANDBOX_LINGER=2400 /opt/microvm/launch-microvms.sh 1000
```

The launcher preflights first — firecracker, KVM, a TUN-capable kernel, the
rootfs, the binaries and a non-empty bootstrap token — then starts one `sam-box`
per agent and one microVM per `sam-box`, all against a single node. The rootfs
is shared read-only: a private 500 MB copy per agent is half a terabyte at a
thousand agents, and the disk runs out before the memory does.

`SANDBOX_LINGER` holds each sandbox open after its agent finishes. A density
measurement needs the population resident *at the same time*; left alone a
sandbox powers off the moment it is done, so a thousand started in sequence are
never a thousand at once. Zero is the right value for real work.

Useful knobs, all environment variables:

| | |
| --- | --- |
| `VM_MEM_MIB` | Guest memory, default 160 |
| `SANDBOX_LINGER` | Seconds to hold a sandbox after the agent exits, default 0 |
| `SAM_MODEL` | Model to ask the mesh for; unset takes whatever the catalog offers |
| `CONTROL_PLANE` | Defaults to the `bananas` testnet |
| `AGENT_DOMAIN` | The domain agents are named under |

These reach the guest as kernel command-line pairs, which is the only way to
tell PID 1 anything — it is started with an empty environment. They therefore
**cannot contain spaces**, and the launcher rejects values that do.

---

## Step 5: collect

```bash
sudo tests/scale/collect-fleet.sh \
  --node-socket /var/run/sam-node.sock --duration 1500 --out fleet.jsonl
```

The headline number is how many agents the *node* is serving, not how many
microVMs somebody started: a guest that booted and never reached its boundary is
a process, not an agent. This asks the node, and samples over time rather than
once at the end, because the shape of the curve is what says whether a
population came up smoothly or fell over partway.

Watch `sam_node_agents_untracked_total`. If it is anything but zero, the agent
count is a ceiling rather than a measurement.

---

## Step 6: drive load

Density is not throughput. With the fleet resident:

```bash
sudo tests/scale/load-fleet.sh --agents 200 --requests 200 --out /var/log/load
sudo tests/scale/load-fleet.sh --report /var/log/load
```

Load goes through one boundary per agent rather than many connections through
one, so the node sees *N* distinct principals and the admission path is
exercised as it would be in practice. Pointing a single generator at a single
boundary measures a socket, not a mesh.

---

## Watching it

```bash
# Did the host finish setting itself up?
sudo tail -f /var/log/startup-script.log

# A guest's console, agent output included
sudo tail -f /var/log/fc-vm-1.log

# What the node thinks it is serving
sudo curl -s --unix-socket /var/run/sam-node.sock http://localhost/metrics \
  | grep sam_node_agents_seen
```

---

## The boundary measurements

The other half of the report needs no cloud at all. It stands up a real mesh on
kind and attaches boundaries to it:

```bash
./tests/scale/run-density.sh --steps 1,2,4,8,16,32,64 --requests 500
```

Results land in `tests/scale/results/`, with `environment.json`, the raw
per-step observations and a rendered `table.md`.

---

## Chaos testing

`cmd/chaos-agent` is a LangChain agent pointed at whatever tools the mesh grants
it and told to abuse them. It is the right tool for asking whether the mesh
survives an autonomous caller, and the wrong one for asking what anything costs.

```bash
ROOTFS_MB=2048 AGENT_SRC=cmd/chaos-agent ./scripts/build-rootfs.sh

sudo SAM_MODEL=google/gemma-2-2b-it CHAOS_SLEEP=30 VM_MEM_MIB=512 \
     /opt/microvm/launch-microvms.sh 25
```

It runs until stopped, sleeping a jittered interval between rounds so a fleet of
them does not arrive at the providers in lockstep, and it treats its own crashes
as data rather than as a reason to exit. Like the harness it holds no
credentials, addresses everything by mesh name, and takes its model from the
catalog rather than being told one.
