# sam-mesh Helm chart

Deploys a self-contained SAM mesh (control plane, router, console, and
optionally an in-cluster Postgres + Dex) for local development, testing, or
self-hosting your own hub.

> For large-scale production deployments (GKE/EKS/AKS) using externally
> managed Postgres/DNS/OIDC, see the
> [Production Kubernetes Deployment guide](https://sam-mesh.dev/docs/user/kubernetes-deployment/),
> which uses plain manifests instead of this chart.

## Install

```bash
helm upgrade --install sam-mesh ./charts/sam-mesh --namespace sam --create-namespace
```

At the end of `helm install`/`helm upgrade`, the chart prints the exact
`kubectl` command to retrieve your generated secrets (see below) — read the
NOTES output before doing anything else.

## Secrets: `controlPlane.adminToken` and `database.postgres.password`

Both default to `""` in [values.yaml](values.yaml). When left blank, the chart
**auto-generates** a random 32-character secret on first install and stores it
in the `<release>-secrets` Kubernetes Secret; the same value is reused on
`helm upgrade` (it is not rotated on every upgrade). Retrieve the admin token
with:

```bash
kubectl get secret --namespace <namespace> <release>-secrets -o jsonpath='{.data.admin-token}' | base64 -d; echo
```

You can also pin either value explicitly instead of letting the chart
generate one, e.g. for reproducible dev environments or to match an
existing secret:

```bash
helm upgrade --install sam-mesh ./charts/sam-mesh \
  --set controlPlane.adminToken="$(openssl rand -hex 32)" \
  --set database.postgres.password="$(openssl rand -hex 32)"
```

## `controlPlane.insecureSkipTlsVerify`

Defaults to `false`. Only set this to `true` when `controlPlane.oidcIssuer`
points at an OIDC issuer served with a self-signed or otherwise untrusted
certificate — for example the Kubernetes API server's own issuer
(`https://kubernetes.default.svc.cluster.local`) used for ServiceAccount
Workload Identity Federation in local `kind` clusters, or a local Dex/mock
OIDC instance without a real cert. Leave it `false` for any real-world OIDC
provider (Google, Okta, Dex behind a real TLS certificate, etc.).

## `controlPlane.autoApproveEnrollment`

Defaults to `true` (any node/router presenting a valid identity token is
enrolled immediately, no manual step). Set to `false` if you want an
administrator to approve each enrollment via `/admin/enrollments` before a
node can join — see the
[Control Plane Configuration guide](https://sam-mesh.dev/docs/user/control-plane-configuration/#6-headless-node-enrollment-bootstrap-token-flow).

## Gateway API (`gateway.enabled`)

Disabled by default. When enabled the chart creates one `Gateway` per
externally-reachable service — control plane, console and Dex — each with its
own `HTTPRoute`. `gateway.className` is then **required**, with no default,
because the right GatewayClass is provider-specific (`cloud-provider-kind` in
kind, `gke-l7-global-external-managed` on GKE, `istio`, `envoy-gateway`, …).

The control-plane route exposes only the enrollment surface (`/register`,
`/info`, `/keys`, `/routers/lease`, `/policies`, `/enroll`, `/enroll/status`,
`/refresh`); everything else, including `/admin` and `/user`, is unrouted.
`gateway.adminRoute: true` additionally routes `/admin` — a dev convenience,
leave it off in production. The console and Dex each get a `PathPrefix /` route.

`listeners`, `hostnames`, `addresses` and `annotations` are passed through to
the Gateway API objects verbatim, so anything the spec allows is expressible.
They default to one plain-HTTP listener on port 80 matching every host, which
suits a local cluster. `gateway.controlPlane`, `gateway.console` and
`gateway.dex` override any of the four for that gateway alone — needed when
each hostname has its own certificate or provider annotation:

```yaml
gateway:
  enabled: true
  className: gke-l7-global-external-managed
  listeners:
  - name: https
    protocol: HTTPS
    port: 443
    tls:
      certificateRefs:
      - name: sam-mesh-tls
    allowedRoutes:
      namespaces:
        from: Same
  hostnames: [hub.example.com]
  controlPlane:
    addresses:
    - type: NamedAddress
      value: sam-hub-ip
    annotations:
      networking.gke.io/certmap: sam-hub-cert-map
  console:
    hostnames: [console.example.com]
  dex:
    hostnames: [auth.example.com]
```

No route uses an HTTPRoute filter, so every rule is core conformance and any
compliant controller can serve it.

### Where the console lives (`console.basePath`)

By default the console gets its own gateway and serves at `/`, which keeps it
on a separate hostname or address. Set `console.basePath` to serve it on the
control plane's gateway instead:

```bash
helm upgrade --install sam-mesh ./charts/sam-mesh \
  --set gateway.enabled=true --set gateway.className=<class> \
  --set console.basePath=/console
```

That drops the console's own Gateway and adds a `PathPrefix /console` rule to
the control-plane route, so one address fronts both. The prefix needs **no**
rewrite filter: the chart passes the same value as `--base-path`, and the
console serves that prefix itself (it also keeps serving at the root, so a
proxy that does strip the prefix still works).

When the console is on its own hostname, point `dex.redirectURIs` at
`https://<console-hostname>/auth/callback`; with a `basePath` it becomes
`https://<hub-hostname>/console/auth/callback`. Either way `dex.issuer` must be
the URL clients reach Dex at.

## Dex (`dex.enabled`)

Disabled by default. The bundled Dex is only meant for local/dev OIDC login
(username/password test users); real deployments should point
`controlPlane.oidcIssuer` at your own identity provider instead of enabling
this.
