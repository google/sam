---
title: "Release Tracks, Autoupdate, and Autoscaling"
linkTitle: "Release Tracks, Autoupdate, and Autoscaling"
---
Sovereign Agent Mesh (SAM) is deployed to public endpoints using automated environments, release tracks, and self-healing/scaling infrastructure.

---

## 1. Release Tracks

The public deployment has two isolated release tracks:

### A. Testnet Track (Bananas)
*   **Domain Name:** `bananas.sam-mesh.dev`
*   **Source Branch:** Tracks the `main` branch.
*   **Deployment Trigger:** Automatically deployed on every new push/commit to the `main` branch.
*   **Target Tag:** The deployment is tagged with the Git commit SHA (`github.sha`).
*   **Purpose:** Serves as the staging/testing playground for the latest features and continuous integration.

### B. Production Track (Hub)
*   **Domain Name:** `hub.sam-mesh.dev`
*   **Source Branch:** Tracks semantic version tags matching `v*.*.*`.
*   **Deployment Trigger:** Automatically deployed whenever a new version tag is pushed to GitHub.
*   **Target Tag:** The deployment is tagged with the exact Git release tag (e.g. `v1.0.0`).
*   **Purpose:** Stable, audited release track for production workloads.

---

## 2. Autoupdate Mechanism

Updates to both release tracks are fully automated via a robust **Continuous Deployment** pipeline:

1.  **GitHub Actions Trigger:** The workflow defined in [.github/workflows/deploy.yaml](../.github/workflows/deploy.yaml) is automatically triggered by repository events (pushing to main or pushing a version tag).
2.  **Determining the Track & Tag:**
    *   If the event is a release tag, the pipeline dynamically targets the `hub` GitHub environment and sets the container image tag to the release version.
    *   Otherwise, it targets the `bananas` environment and sets the container image tag to the Git commit SHA.
3.  **Rolling Updates:**
    *   Images are built and pushed to GitHub Container Registry (`ghcr.io`).
    *   The workflow executes `kubectl apply` on the Kubernetes templates.
    *   Kubernetes uses a `RollingUpdate` strategy, updating the pods one-by-one. This guarantees **zero-downtime** updates while replacing running processes with the new version.
    *   The workflow executes `kubectl rollout status` to verify that the new pods become healthy and ready. If an update fails, GKE automatically rolls back to the previous stable version.
