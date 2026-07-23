// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package controlplane

import (
	"encoding/json"
	"net/http"

	"gopkg.in/yaml.v2"
)

// HandleAdminStatus returns a consolidated JSON state of the control plane.
func (s *Server) HandleAdminStatus(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdminAuth(w, r) {
		return
	}

	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx := r.Context()

	routers, err := s.store.GetActiveRouters(ctx)
	if err != nil {
		logger.Errorf("Failed to get active routers: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	nodes, err := s.store.ListNodes(ctx)
	if err != nil {
		logger.Errorf("Failed to list nodes: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	reqs, err := s.store.ListEnrollmentRequests(ctx)
	if err != nil {
		logger.Errorf("Failed to list enrollment requests: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	tokens, err := s.store.ListBootstrapTokens(ctx)
	if err != nil {
		logger.Errorf("Failed to list bootstrap tokens: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	roles, bindings, err := s.store.GetMeshPolicy(r.Context())
	if err != nil {
		logger.Errorf("Failed to list policy: %v", err)
	}

	type displayRole struct {
		AllowedServices []string `yaml:"allowed_services"`
		AllowedTargets  []string `yaml:"allowed_targets"`
	}
	type displayBinding struct {
		Role    string   `yaml:"role"`
		Members []string `yaml:"members"`
	}
	displayMap := map[string]interface{}{
		"roles":    make(map[string]displayRole),
		"bindings": make([]displayBinding, 0),
	}

	for _, role := range roles {
		displayMap["roles"].(map[string]displayRole)[role.Name] = displayRole{
			AllowedServices: role.AllowedServices,
			AllowedTargets:  role.AllowedTargets,
		}
	}
	for _, b := range bindings {
		displayMap["bindings"] = append(displayMap["bindings"].([]displayBinding), displayBinding{
			Role:    b.Role,
			Members: b.Members,
		})
	}

	var policyYAML string
	yamlBytes, err := yaml.Marshal(displayMap)
	if err == nil {
		policyYAML = string(yamlBytes)
	}

	resp := map[string]any{
		"active_routers":      routers,
		"enrolled_nodes":      nodes,
		"enrollment_requests": reqs,
		"bootstrap_tokens":    tokens,
		"policy_yaml":         policyYAML,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// HandleAdminUI serves the dashboard single page web app.
func (s *Server) HandleAdminUI(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/admin" {
		http.Redirect(w, r, "/admin/", http.StatusMovedPermanently)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(adminHTML))
}

const adminHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SAM Control Plane Admin</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-primary: #070614;
            --bg-secondary: #0f0d26;
            --bg-card: rgba(22, 20, 48, 0.5);
            --border-color: rgba(255, 255, 255, 0.06);
            --text-primary: #f1f1f7;
            --text-secondary: #8c8aa7;
            --accent: linear-gradient(135deg, #6366f1, #a855f7);
            --accent-solid: #6366f1;
            --green: #10b981;
            --red: #f43f5e;
            --amber: #f59e0b;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
            font-family: 'Inter', sans-serif;
        }

        body {
            background-color: var(--bg-primary);
            background-image: radial-gradient(circle at 10% 20%, rgba(99, 102, 241, 0.1) 0%, transparent 40%),
                              radial-gradient(circle at 90% 80%, rgba(168, 85, 247, 0.08) 0%, transparent 40%);
            background-attachment: fixed;
            color: var(--text-primary);
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            overflow-x: hidden;
        }

        header {
            background: rgba(15, 13, 38, 0.7);
            backdrop-filter: blur(12px);
            border-bottom: 1px solid var(--border-color);
            padding: 1.25rem 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            position: sticky;
            top: 0;
            z-index: 100;
        }

        .header-title {
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }

        .header-title h1 {
            font-size: 1.25rem;
            font-weight: 700;
            letter-spacing: -0.025em;
            background: var(--accent);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .status-badge {
            background: rgba(16, 185, 129, 0.15);
            color: var(--green);
            font-size: 0.75rem;
            padding: 0.25rem 0.6rem;
            border-radius: 9999px;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 0.35rem;
            border: 1px solid rgba(16, 185, 129, 0.25);
        }

        .status-badge::before {
            content: '';
            display: inline-block;
            width: 6px;
            height: 6px;
            background-color: var(--green);
            border-radius: 50%;
            box-shadow: 0 0 8px var(--green);
            animation: pulse 1.5s infinite;
        }

        @keyframes pulse {
            0% { transform: scale(0.95); opacity: 0.5; }
            50% { transform: scale(1.2); opacity: 1; }
            100% { transform: scale(0.95); opacity: 0.5; }
        }

        .header-actions {
            display: flex;
            align-items: center;
            gap: 1rem;
        }

        .btn {
            background: var(--accent);
            border: none;
            color: white;
            padding: 0.6rem 1.2rem;
            border-radius: 8px;
            font-weight: 600;
            font-size: 0.875rem;
            cursor: pointer;
            transition: all 0.2s ease;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .btn:hover {
            transform: translateY(-1px);
            box-shadow: 0 4px 12px rgba(99, 102, 241, 0.3);
        }

        .btn-secondary {
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid var(--border-color);
            color: var(--text-primary);
        }

        .btn-secondary:hover {
            background: rgba(255, 255, 255, 0.08);
            box-shadow: none;
        }

        .btn-danger {
            background: var(--red);
        }

        .btn-danger:hover {
            box-shadow: 0 4px 12px rgba(244, 63, 94, 0.3);
        }

        .container {
            flex: 1;
            max-width: 1400px;
            width: 100%;
            margin: 0 auto;
            padding: 2rem;
            display: flex;
            gap: 2rem;
        }

        .sidebar {
            width: 250px;
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
            flex-shrink: 0;
        }

        .nav-item {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            padding: 0.8rem 1rem;
            border-radius: 8px;
            color: var(--text-secondary);
            text-decoration: none;
            font-weight: 500;
            font-size: 0.95rem;
            cursor: pointer;
            transition: all 0.2s ease;
            background: transparent;
            border: none;
            text-align: left;
            width: 100%;
        }

        .nav-item:hover, .nav-item.active {
            color: var(--text-primary);
            background: rgba(255, 255, 255, 0.04);
        }

        .nav-item.active {
            background: rgba(99, 102, 241, 0.1);
            color: var(--accent-solid);
            border-left: 3px solid var(--accent-solid);
            padding-left: calc(1rem - 3px);
        }

        .main-content {
            flex: 1;
            min-width: 0;
            display: flex;
            flex-direction: column;
            gap: 2rem;
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 1.5rem;
        }

        .stat-card {
            background: var(--bg-card);
            backdrop-filter: blur(8px);
            border: 1px solid var(--border-color);
            padding: 1.5rem;
            border-radius: 12px;
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
        }

        .stat-label {
            font-size: 0.8rem;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 0.05em;
            font-weight: 600;
        }

        .stat-value {
            font-size: 1.8rem;
            font-weight: 700;
            color: var(--text-primary);
        }

        .stat-badge {
            align-self: flex-start;
            font-size: 0.7rem;
            font-weight: 600;
            padding: 0.15rem 0.4rem;
            border-radius: 4px;
            background: rgba(255, 255, 255, 0.05);
        }

        .card {
            background: var(--bg-card);
            backdrop-filter: blur(8px);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            overflow: hidden;
            display: none;
            animation: fadeIn 0.3s ease-in-out;
        }

        .card.active {
            display: flex;
            flex-direction: column;
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(4px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .card-header {
            padding: 1.5rem;
            border-bottom: 1px solid var(--border-color);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .card-title {
            font-size: 1.1rem;
            font-weight: 600;
        }

        .card-body {
            padding: 1.5rem;
        }

        /* Table styles */
        .table-container {
            overflow-x: auto;
            width: 100%;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            text-align: left;
        }

        th {
            padding: 0.75rem 1rem;
            color: var(--text-secondary);
            font-weight: 600;
            font-size: 0.8rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            border-bottom: 1px solid var(--border-color);
        }

        td {
            padding: 1rem;
            border-bottom: 1px solid rgba(255, 255, 255, 0.03);
            font-size: 0.9rem;
            vertical-align: middle;
        }

        tr:last-child td {
            border-bottom: none;
        }

        .peer-id-cell {
            font-family: monospace;
            color: var(--accent-solid);
            background: rgba(99, 102, 241, 0.05);
            padding: 0.2rem 0.4rem;
            border-radius: 4px;
            font-size: 0.85rem;
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
        }

        .copy-btn {
            background: transparent;
            border: none;
            color: var(--text-secondary);
            cursor: pointer;
            transition: color 0.2s;
        }

        .copy-btn:hover {
            color: var(--text-primary);
        }

        .badge {
            font-size: 0.75rem;
            padding: 0.2rem 0.5rem;
            border-radius: 6px;
            font-weight: 600;
            display: inline-block;
        }

        .badge-router { background: rgba(168, 85, 247, 0.15); color: #c084fc; border: 1px solid rgba(168, 85, 247, 0.25); }
        .badge-node { background: rgba(99, 102, 241, 0.15); color: #818cf8; border: 1px solid rgba(99, 102, 241, 0.25); }
        .badge-pending { background: rgba(245, 158, 11, 0.15); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.25); }
        .badge-approved { background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.25); }
        .badge-rejected { background: rgba(244, 63, 94, 0.15); color: #fb7185; border: 1px solid rgba(244, 63, 94, 0.25); }
        .badge-banned { background: rgba(244, 63, 94, 0.2); color: #fda4af; border: 1px solid rgba(244, 63, 94, 0.3); }

        /* Router specific card dashboard grid */
        .router-cards-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
            gap: 1.5rem;
        }

        .router-item-card {
            background: rgba(255, 255, 255, 0.02);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 1.25rem;
            display: flex;
            flex-direction: column;
            gap: 0.75rem;
        }

        .router-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .router-peer-id {
            font-family: monospace;
            font-weight: 600;
            font-size: 0.85rem;
            color: var(--text-primary);
        }

        .router-metrics {
            display: flex;
            gap: 1rem;
            background: rgba(0,0,0,0.2);
            padding: 0.5rem;
            border-radius: 6px;
            font-size: 0.8rem;
        }

        .router-metric-item {
            flex: 1;
            text-align: center;
        }

        .router-metric-val {
            font-size: 1rem;
            font-weight: 700;
            color: var(--accent-solid);
        }

        .router-peers-list {
            font-size: 0.75rem;
            color: var(--text-secondary);
            max-height: 80px;
            overflow-y: auto;
            padding-left: 1.25rem;
        }

        /* Form styling */
        .form-group {
            margin-bottom: 1.25rem;
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
        }

        label {
            font-size: 0.85rem;
            font-weight: 600;
            color: var(--text-secondary);
        }

        input, select, textarea {
            background: rgba(0, 0, 0, 0.3);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            color: var(--text-primary);
            padding: 0.75rem;
            font-size: 0.9rem;
            transition: all 0.2s;
            width: 100%;
        }

        input:focus, select:focus, textarea:focus {
            outline: none;
            border-color: var(--accent-solid);
            box-shadow: 0 0 0 2px rgba(99, 102, 241, 0.15);
        }

        /* Policy YAML textarea styling */
        .yaml-editor-container {
            display: flex;
            flex-direction: column;
            gap: 1rem;
            height: 500px;
        }

        .yaml-editor {
            font-family: 'Courier New', Courier, monospace;
            font-size: 0.9rem;
            resize: none;
            background: #05040d;
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 1rem;
            line-height: 1.4;
            color: #d8b4fe;
        }

        /* Modal styling */
        .modal-overlay {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(5, 4, 16, 0.8);
            backdrop-filter: blur(12px);
            z-index: 1000;
            display: flex;
            align-items: center;
            justify-content: center;
            opacity: 0;
            pointer-events: none;
            transition: opacity 0.3s ease;
        }

        .modal-overlay.active {
            opacity: 1;
            pointer-events: auto;
        }

        .modal {
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            width: 90%;
            max-width: 450px;
            padding: 2rem;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5);
            display: flex;
            flex-direction: column;
            gap: 1.5rem;
            transform: scale(0.95);
            transition: transform 0.3s ease;
        }

        .modal-overlay.active .modal {
            transform: scale(1);
        }

        .modal-header h2 {
            font-size: 1.25rem;
            font-weight: 700;
        }

        /* Toast notifications */
        .toast-container {
            position: fixed;
            bottom: 2rem;
            right: 2rem;
            display: flex;
            flex-direction: column;
            gap: 0.75rem;
            z-index: 2000;
        }

        .toast {
            background: rgba(22, 20, 48, 0.9);
            border-left: 4px solid var(--accent-solid);
            border-top: 1px solid var(--border-color);
            border-right: 1px solid var(--border-color);
            border-bottom: 1px solid var(--border-color);
            color: var(--text-primary);
            padding: 1rem 1.5rem;
            border-radius: 0 8px 8px 0;
            font-size: 0.9rem;
            font-weight: 500;
            box-shadow: 0 4px 15px rgba(0,0,0,0.3);
            display: flex;
            align-items: center;
            gap: 0.75rem;
            transform: translateY(20px);
            opacity: 0;
            animation: slideIn 0.3s forwards ease-out;
        }

        @keyframes slideIn {
            to { transform: translateY(0); opacity: 1; }
        }

        .toast.success { border-left-color: var(--green); }
        .toast.error { border-left-color: var(--red); }
    </style>
</head>
<body>

    <header>
        <div class="header-title">
            <h1>Sovereign Agent Mesh</h1>
            <span class="status-badge">Control Plane</span>
        </div>
        <div class="header-actions">
            <button class="btn btn-secondary" onclick="openTokenModal()">Set Auth Token</button>
            <button class="btn btn-danger" onclick="logout()" id="logout-btn" style="display: none;">Logout</button>
        </div>
    </header>

    <div class="container">
        <aside class="sidebar">
            <button class="nav-item active" onclick="switchTab('tab-overview', this)">Overview</button>
            <button class="nav-item" onclick="switchTab('tab-requests', this)" id="nav-requests">Enrollments Queue <span id="req-badge" class="badge badge-pending" style="display: none; margin-left: 0.25rem;">0</span></button>
            <button class="nav-item" onclick="switchTab('tab-nodes', this)">Enrolled Nodes</button>
            <button class="nav-item" onclick="switchTab('tab-routers', this)">Active Routers</button>
            <button class="nav-item" onclick="switchTab('tab-bootstrap', this)">Bootstrap Tokens</button>
            <button class="nav-item" onclick="switchTab('tab-policy', this)">Mesh Policy</button>
        </aside>

        <main class="main-content">
            <!-- Stats overview -->
            <div class="stats-grid">
                <div class="stat-card">
                    <span class="stat-label">Active Nodes</span>
                    <span class="stat-value" id="stat-active-nodes">0</span>
                    <span class="stat-badge" id="stat-banned-nodes">0 Banned</span>
                </div>
                <div class="stat-card">
                    <span class="stat-label">Active Routers</span>
                    <span class="stat-value" id="stat-active-routers">0</span>
                    <span class="stat-badge" id="stat-total-connections">0 Connected Peers</span>
                </div>
                <div class="stat-card">
                    <span class="stat-label">Pending Enrollments</span>
                    <span class="stat-value" id="stat-pending-reqs">0</span>
                    <span class="stat-badge" id="stat-resolved-reqs">0 Resolved</span>
                </div>
                <div class="stat-card">
                    <span class="stat-label">Bootstrap Tokens</span>
                    <span class="stat-value" id="stat-tokens">0</span>
                    <span class="stat-badge">Pre-Shared Auth</span>
                </div>
            </div>

            <!-- TAB: Overview -->
            <div class="card active" id="tab-overview">
                <div class="card-header">
                    <h2 class="card-title">Network Topography Overview</h2>
                </div>
                <div class="card-body">
                    <div id="router-topography-list" class="router-cards-grid">
                        <!-- Router list cards will be rendered dynamically -->
                    </div>
                </div>
            </div>

            <!-- TAB: Enrollment requests -->
            <div class="card" id="tab-requests">
                <div class="card-header">
                    <h2 class="card-title">Pending Enrollments Queue</h2>
                </div>
                <div class="card-body">
                    <div class="table-container">
                        <table>
                            <thead>
                                <tr>
                                    <th>Peer ID</th>
                                    <th>Token ID</th>
                                    <th>Created At</th>
                                    <th>Status</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody id="enrollments-tbody">
                                <!-- Dynamic rows -->
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>

            <!-- TAB: Enrolled Nodes -->
            <div class="card" id="tab-nodes">
                <div class="card-header">
                    <h2 class="card-title">Enrolled Mesh Nodes</h2>
                </div>
                <div class="card-body">
                    <div class="table-container">
                        <table>
                            <thead>
                                <tr>
                                    <th>Peer ID</th>
                                    <th>Role</th>
                                    <th>Type</th>
                                    <th>Enrolled At</th>
                                    <th>Expires At</th>
                                    <th>Status</th>
                                    <th>Action</th>
                                </tr>
                            </thead>
                            <tbody id="nodes-tbody">
                                <!-- Dynamic rows -->
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>

            <!-- TAB: Active Routers -->
            <div class="card" id="tab-routers">
                <div class="card-header">
                    <h2 class="card-title">Active Mesh Routers (Leases)</h2>
                </div>
                <div class="card-body">
                    <div class="table-container">
                        <table>
                            <thead>
                                <tr>
                                    <th>Peer ID</th>
                                    <th>Multiaddresses</th>
                                    <th>Last Renewal</th>
                                    <th>Expires At</th>
                                    <th>DHT Size</th>
                                    <th>Connected Peers</th>
                                </tr>
                            </thead>
                            <tbody id="routers-tbody">
                                <!-- Dynamic rows -->
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>

            <!-- TAB: Bootstrap Tokens -->
            <div class="card" id="tab-bootstrap">
                <div class="card-header">
                    <h2 class="card-title">Generate Bootstrap Token</h2>
                </div>
                <div class="card-body" style="display: flex; flex-direction: column; gap: 2rem;">
                    <form id="token-form" onsubmit="generateToken(event)">
                        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem;">
                            <div class="form-group">
                                <label for="token-role">Role</label>
                                <select id="token-role">
                                    <option value="sam:role:node">sam:role:node</option>
                                    <option value="sam:role:router">sam:role:router</option>
                                </select>
                            </div>
                            <div class="form-group">
                                <label for="token-ttl">TTL (Hours)</label>
                                <input type="number" id="token-ttl" value="24" min="1">
                            </div>
                        </div>
                        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem;">
                            <div class="form-group">
                                <label for="token-usages">Max Usages</label>
                                <input type="number" id="token-usages" value="1" min="1">
                            </div>
                            <div class="form-group">
                                <label for="token-desc">Description</label>
                                <input type="text" id="token-desc" placeholder="e.g. For router VM bootstrap">
                            </div>
                        </div>
                        <button type="submit" class="btn" style="margin-top: 0.5rem;">Generate Token</button>
                    </form>

                    <div style="border-top: 1px solid var(--border-color); padding-top: 1.5rem;">
                        <h3 style="margin-bottom: 1rem; font-size: 1rem; font-weight: 600;">Active Bootstrap Tokens</h3>
                        <div class="table-container">
                            <table>
                                <thead>
                                    <tr>
                                        <th>ID Hash</th>
                                        <th>Role</th>
                                        <th>Usages</th>
                                        <th>Expires At</th>
                                        <th>Description</th>
                                    </tr>
                                </thead>
                                <tbody id="tokens-tbody">
                                    <!-- Dynamic rows -->
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>

            <!-- TAB: Mesh Policy -->
            <div class="card" id="tab-policy">
                <div class="card-header">
                    <h2 class="card-title">Mesh Security Policies Configuration</h2>
                </div>
                <div class="card-body yaml-editor-container">
                    <textarea class="yaml-editor" id="policy-yaml" placeholder="# Loading policy configuration..."></textarea>
                    <button class="btn" onclick="savePolicy()">Save & Apply Policy</button>
                </div>
            </div>
        </main>
    </div>

    <!-- Modal for Admin Token -->
    <div class="modal-overlay" id="token-modal">
        <div class="modal">
            <div class="modal-header">
                <h2>Control Plane Authentication</h2>
            </div>
            <div class="form-group">
                <label for="admin-token-input">Admin Token (Bearer Key)</label>
                <input type="password" id="admin-token-input" placeholder="Enter admin authorization token">
            </div>
            <div style="display: flex; gap: 1rem; justify-content: flex-end;">
                <button class="btn btn-secondary" onclick="closeTokenModal()">Cancel</button>
                <button class="btn" onclick="saveAdminToken()">Save Token</button>
            </div>
        </div>
    </div>

    <!-- Toast Notifications Container -->
    <div class="toast-container" id="toast-container"></div>

    <script>
        function escapeHTML(str) {
            if (!str) return '';
            return str.replace(/[&<>"']/g, function(m) {
                switch (m) {
                    case '&': return '&amp;';
                    case '<': return '&lt;';
                    case '>': return '&gt;';
                    case '"': return '&quot;';
                    case "'": return '&#039;';
                    default: return m;
                }
            });
        }

        let adminToken = localStorage.getItem('sam_admin_token') || '';
        let modalCancelled = false;

        function writeVarint(value) {
            const bytes = [];
            while (value > 127) {
                bytes.push((value & 127) | 128);
                value >>>= 7;
            }
            bytes.push(value);
            return bytes;
        }

        function showToast(message, type) {
            type = type || 'success';
            const container = document.getElementById('toast-container');
            const toast = document.createElement('div');
            toast.className = 'toast ' + type;
            toast.textContent = message;
            container.appendChild(toast);
            setTimeout(function() {
                toast.style.opacity = '0';
                toast.style.transform = 'translateY(10px)';
                setTimeout(function() { toast.remove(); }, 300);
            }, 3000);
        }

        function openTokenModal() {
            modalCancelled = false;
            document.getElementById('admin-token-input').value = adminToken;
            document.getElementById('token-modal').classList.add('active');
        }

        function closeTokenModal() {
            document.getElementById('token-modal').classList.remove('active');
            modalCancelled = true;
        }

        function saveAdminToken() {
            const val = document.getElementById('admin-token-input').value.trim();
            adminToken = val;
            localStorage.setItem('sam_admin_token', val);
            document.getElementById('logout-btn').style.display = val ? 'block' : 'none';
            closeTokenModal();
            showToast('Authorization token updated');
            fetchData();
        }

        function logout() {
            adminToken = '';
            localStorage.removeItem('sam_admin_token');
            document.getElementById('logout-btn').style.display = 'none';
            showToast('Authorization cleared');
            fetchData();
        }

        if (adminToken) {
            document.getElementById('logout-btn').style.display = 'block';
        }

        function switchTab(tabId, el) {
            document.querySelectorAll('.card').forEach(function(c) { c.classList.remove('active'); });
            document.querySelectorAll('.nav-item').forEach(function(n) { n.classList.remove('active'); });
            document.getElementById(tabId).classList.add('active');
            el.classList.add('active');
        }

        function copyToClipboard(text) {
            if (!navigator.clipboard) {
                const textArea = document.createElement("textarea");
                textArea.value = text;
                textArea.style.position = "fixed";
                document.body.appendChild(textArea);
                textArea.focus();
                textArea.select();
                try {
                    document.execCommand('copy');
                    showToast('Copied to clipboard');
                } catch (err) {
                    showToast('Failed to copy', 'error');
                }
                document.body.removeChild(textArea);
                return;
            }
            navigator.clipboard.writeText(text).then(function() {
                showToast('Copied to clipboard');
            }).catch(function(err) {
                showToast('Failed to copy', 'error');
            });
        }

        async function apiCall(endpoint, method, body) {
            method = method || 'GET';
            body = body || null;
            const headers = {};
            if (adminToken) {
                headers['Authorization'] = 'Bearer ' + adminToken;
            }
            if (body && typeof body === 'object') {
                headers['Content-Type'] = 'application/json';
            }

            const options = { method: method, headers: headers };
            if (body) {
                options.body = typeof body === 'object' ? JSON.stringify(body) : body;
            }

            try {
                const response = await fetch(endpoint, options);
                if (response.status === 401) {
                    showToast('Unauthorized: Check your admin token', 'error');
                    if (!modalCancelled) {
                        openTokenModal();
                    }
                    return null;
                }
                if (!response.ok) {
                    const text = await response.text();
                    showToast(text || 'API call failed', 'error');
                    return null;
                }
                if (response.headers.get('Content-Type') && response.headers.get('Content-Type').includes('application/json')) {
                    return await response.json();
                }
                return await response.text();
            } catch (err) {
                showToast('Network error: ' + err.message, 'error');
                return null;
            }
        }

        async function fetchData() {
            const data = await apiCall('/admin/status');
            if (!data) return;

            // Update stats indicators
            const nodes = data.enrolled_nodes || [];
            const activeNodes = nodes.filter(function(n) { return !n.Banned; });
            const bannedNodes = nodes.filter(function(n) { return n.Banned; });
            document.getElementById('stat-active-nodes').textContent = activeNodes.length;
            document.getElementById('stat-banned-nodes').textContent = bannedNodes.length + ' Banned';

            const routers = data.active_routers || [];
            document.getElementById('stat-active-routers').textContent = routers.length;
            let peerCount = 0;
            routers.forEach(function(r) {
                if (r.ConnectedPeers) {
                    peerCount += r.ConnectedPeers.length;
                }
            });
            document.getElementById('stat-total-connections').textContent = peerCount + ' Connected Peers';

            const reqs = data.enrollment_requests || [];
            const pendingReqs = reqs.filter(function(r) { return r.Status === 1; }); // PENDING
            const resolvedReqs = reqs.filter(function(r) { return r.Status !== 1; });
            document.getElementById('stat-pending-reqs').textContent = pendingReqs.length;
            document.getElementById('stat-resolved-reqs').textContent = resolvedReqs.length + ' Resolved';
            
            const reqBadge = document.getElementById('req-badge');
            if (pendingReqs.length > 0) {
                reqBadge.textContent = pendingReqs.length;
                reqBadge.style.display = 'inline-block';
            } else {
                reqBadge.style.display = 'none';
            }

            const tokens = data.bootstrap_tokens || [];
            document.getElementById('stat-tokens').textContent = tokens.length;

            // Render Overview / Topography list
            const topoList = document.getElementById('router-topography-list');
            topoList.innerHTML = '';
            if (routers.length === 0) {
                topoList.innerHTML = '<div style="grid-column: 1/-1; text-align: center; color: var(--text-secondary); padding: 2rem;">No active routers online in the mesh.</div>';
            } else {
                routers.forEach(function(r) {
                    const conns = r.ConnectedPeers || [];
                    const dhtSize = r.DHTSize || 0;
                    const elapsed = Math.max(0, Math.floor((new Date(r.ExpiresAt) - new Date()) / 1000));
                    
                    let peersHTML = '';
                    if (conns.length === 0) {
                        peersHTML = '<li>No connected peers</li>';
                    } else {
                        conns.forEach(function(p) {
                            peersHTML += '<li>' + escapeHTML(p.substring(0, 15)) + '... (' + escapeHTML(p.substring(p.length - 8)) + ')</li>';
                        });
                    }

                    topoList.innerHTML += 
                        '<div class="router-item-card">' +
                            '<div class="router-header">' +
                                '<span class="router-peer-id" title="' + escapeHTML(r.PeerID) + '">' + escapeHTML(r.PeerID.substring(0, 12)) + '...' + escapeHTML(r.PeerID.substring(r.PeerID.length - 8)) + '</span>' +
                                '<span class="status-badge" style="background: rgba(16,185,129,0.1); color: var(--green); border-color: rgba(16,185,129,0.15)">Lease: ' + elapsed + 's</span>' +
                            '</div>' +
                            '<div class="router-metrics">' +
                                '<div class="router-metric-item">' +
                                    '<div class="router-metric-val">' + conns.length + '</div>' +
                                    '<div style="font-size: 0.7rem; color: var(--text-secondary)">Connections</div>' +
                                '</div>' +
                                '<div class="router-metric-item" style="border-left: 1px solid var(--border-color)">' +
                                    '<div class="router-metric-val">' + dhtSize + '</div>' +
                                    '<div style="font-size: 0.7rem; color: var(--text-secondary)">DHT Size</div>' +
                                '</div>' +
                            '</div>' +
                            '<div style="font-size: 0.8rem; font-weight: 600; color: var(--text-secondary)">Connected Peers:</div>' +
                            '<ul class="router-peers-list">' + peersHTML + '</ul>' +
                        '</div>';
                });
            }

            // Render Enrollments Queue
            const enrollTbody = document.getElementById('enrollments-tbody');
            enrollTbody.innerHTML = '';
            if (reqs.length === 0) {
                enrollTbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-secondary);">No enrollment requests found.</td></tr>';
            } else {
                reqs.forEach(function(r) {
                    let statusBadge = '';
                    let actionButtons = '';
                    const dateStr = new Date(r.CreatedAt).toLocaleString();

                    const escapedID = escapeHTML(r.ID);
                    const escapedPeerID = escapeHTML(r.PeerID);
                    const escapedResolvedBy = escapeHTML(r.ResolvedBy || '');

                    if (r.Status === 1) { // PENDING
                        statusBadge = '<span class="badge badge-pending">PENDING</span>';
                        actionButtons = 
                            '<button class="btn btn-secondary" style="padding: 0.4rem 0.8rem; font-size: 0.75rem; background: var(--green);" onclick="resolveEnrollment(\'' + escapedID + '\', \'approve\')">Approve</button>' +
                            '<button class="btn btn-danger" style="padding: 0.4rem 0.8rem; font-size: 0.75rem;" onclick="resolveEnrollment(\'' + escapedID + '\', \'reject\')">Reject</button>';
                    } else if (r.Status === 2) { // APPROVED
                        statusBadge = '<span class="badge badge-approved">APPROVED</span>';
                        actionButtons = '<span style="font-size:0.8rem; color:var(--text-secondary)">By ' + escapedResolvedBy + '</span>';
                    } else if (r.Status === 3) { // REJECTED
                        statusBadge = '<span class="badge badge-rejected">REJECTED</span>';
                        actionButtons = '<span style="font-size:0.8rem; color:var(--text-secondary)">By ' + escapedResolvedBy + '</span>';
                    }

                    enrollTbody.innerHTML += 
                        '<tr>' +
                            '<td>' +
                                '<div class="peer-id-cell">' +
                                    '<span>' + escapedPeerID.substring(0, 16) + '...</span>' +
                                    '<button class="copy-btn" onclick="copyToClipboard(\'' + escapedPeerID + '\')">📋</button>' +
                                '</div>' +
                            '</td>' +
                            '<td style="font-family: monospace; font-size:0.8rem;">' + (r.TokenID ? escapeHTML(r.TokenID).substring(0, 8) + '...' : 'OIDC') + '</td>' +
                            '<td>' + dateStr + '</td>' +
                            '<td>' + statusBadge + '</td>' +
                            '<td style="display: flex; gap: 0.5rem;">' + actionButtons + '</td>' +
                        '</tr>';
                });
            }

            // Render Enrolled Nodes
            const nodesTbody = document.getElementById('nodes-tbody');
            nodesTbody.innerHTML = '';
            if (nodes.length === 0) {
                nodesTbody.innerHTML = '<tr><td colspan="7" style="text-align: center; color: var(--text-secondary);">No nodes registered.</td></tr>';
            } else {
                nodes.forEach(function(n) {
                    const statusBadge = n.Banned ? '<span class="badge badge-rejected">BANNED</span>' : '<span class="badge badge-approved">ACTIVE</span>';
                    const enrollDate = new Date(n.EnrolledAt).toLocaleString();
                    const expiryDate = n.ExpiresAt && !n.ExpiresAt.startsWith('0001') ? new Date(n.ExpiresAt).toLocaleString() : 'Never';
                    const roleBadge = n.Role.includes('router') ? 'badge-router' : 'badge-node';
                    
                    const escapedPeerID = escapeHTML(n.PeerID);
                    const escapedRole = escapeHTML(n.Role);
                    const escapedType = escapeHTML(n.EnrollmentType);
                    
                    const actionBtn = n.Banned 
                        ? '<button class="btn btn-secondary" style="padding: 0.35rem 0.75rem; font-size: 0.75rem;" onclick="toggleBan(\'' + escapedPeerID + '\', false)">Unban</button>'
                        : '<button class="btn btn-danger" style="padding: 0.35rem 0.75rem; font-size: 0.75rem;" onclick="toggleBan(\'' + escapedPeerID + '\', true)">Ban</button>';

                    nodesTbody.innerHTML += 
                        '<tr>' +
                            '<td>' +
                                '<div class="peer-id-cell">' +
                                    '<span>' + escapedPeerID.substring(0, 16) + '...</span>' +
                                    '<button class="copy-btn" onclick="copyToClipboard(\'' + escapedPeerID + '\')">📋</button>' +
                                '</div>' +
                            '</td>' +
                            '<td><span class="badge ' + roleBadge + '">' + escapedRole + '</span></td>' +
                            '<td><span style="font-weight:600; font-size:0.8rem;">' + escapedType + '</span></td>' +
                            '<td>' + enrollDate + '</td>' +
                            '<td>' + expiryDate + '</td>' +
                            '<td>' + statusBadge + '</td>' +
                            '<td>' + actionBtn + '</td>' +
                        '</tr>';
                });
            }

            // Render Routers list table
            const routersTbody = document.getElementById('routers-tbody');
            routersTbody.innerHTML = '';
            if (routers.length === 0) {
                routersTbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--text-secondary);">No active routers online.</td></tr>';
            } else {
                routers.forEach(function(r) {
                    const addressesHTML = r.Addresses.map(function(a) { return '<div style="font-family: monospace; font-size:0.75rem; margin-bottom: 0.2rem;">' + escapeHTML(a) + '</div>'; }).join('');
                    const renewalDate = new Date(r.LastRenewal).toLocaleTimeString();
                    const expiryDate = new Date(r.ExpiresAt).toLocaleTimeString();
                    const conns = r.ConnectedPeers || [];
                    const dhtSize = r.DHTSize || 0;

                    const escapedPeerID = escapeHTML(r.PeerID);

                    routersTbody.innerHTML += 
                        '<tr>' +
                            '<td>' +
                                '<div class="peer-id-cell">' +
                                    '<span>' + escapedPeerID.substring(0, 16) + '...</span>' +
                                    '<button class="copy-btn" onclick="copyToClipboard(\'' + escapedPeerID + '\')">📋</button>' +
                                '</div>' +
                            '</td>' +
                            '<td>' + addressesHTML + '</td>' +
                            '<td>' + renewalDate + '</td>' +
                            '<td>' + expiryDate + '</td>' +
                            '<td style="font-weight: 700; color: var(--accent-solid); text-align: center;">' + dhtSize + '</td>' +
                            '<td style="text-align: center;"><span class="badge badge-node">' + conns.length + ' Peers</span></td>' +
                        '</tr>';
                });
            }

            // Render Bootstrap Tokens
            const tokensTbody = document.getElementById('tokens-tbody');
            tokensTbody.innerHTML = '';
            if (tokens.length === 0) {
                tokensTbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-secondary);">No bootstrap tokens created.</td></tr>';
            } else {
                tokens.forEach(function(t) {
                    const expDate = new Date(t.ExpiresAt).toLocaleString();
                    const usageStr = t.UsagesCount + '/' + t.MaxUsages;

                    const escapedID = escapeHTML(t.ID);
                    const escapedRole = escapeHTML(t.Role);
                    const escapedDesc = escapeHTML(t.Description || '');

                    tokensTbody.innerHTML += 
                        '<tr>' +
                            '<td style="font-family: monospace; font-size:0.8rem;">' + escapedID.substring(0, 16) + '...</td>' +
                            '<td><span class="badge ' + (escapedRole.includes('router') ? 'badge-router' : 'badge-node') + '">' + escapedRole + '</span></td>' +
                            '<td style="font-weight: 600;">' + usageStr + '</td>' +
                            '<td>' + expDate + '</td>' +
                            '<td style="color:var(--text-secondary); font-size:0.8rem;">' + escapedDesc + '</td>' +
                        '</tr>';
                });
            }

            // Update Policy YAML if empty/not edited
            const policyArea = document.getElementById('policy-yaml');
            if (data.policy_yaml && !policyArea.dataset.edited) {
                policyArea.value = data.policy_yaml;
            }
        }

        // Track user typing in policy editor to avoid stomping it
        document.getElementById('policy-yaml').addEventListener('input', function(e) {
            e.target.dataset.edited = "true";
        });

        async function resolveEnrollment(id, action) {
            const res = await apiCall('/admin/enrollments/' + id + '/' + action, 'POST');
            if (res !== null) {
                showToast('Enrollment request ' + action + 'ed');
                fetchData();
            }
        }

        async function toggleBan(peerId, ban) {
            const endpoint = '/admin/revoke';
            const encoder = new TextEncoder();
            const peerIdBytes = encoder.encode(peerId);
            const lenBytes = writeVarint(peerIdBytes.length);
            const pbBytes = new Uint8Array(1 + lenBytes.length + peerIdBytes.length);
            pbBytes[0] = 0x0a;
            pbBytes.set(lenBytes, 1);
            pbBytes.set(peerIdBytes, 1 + lenBytes.length);

            const headers = {};
            if (adminToken) {
                headers['Authorization'] = 'Bearer ' + adminToken;
            }
            headers['Content-Type'] = 'application/x-protobuf';

            try {
                const response = await fetch(endpoint, {
                    method: 'POST',
                    headers: headers,
                    body: pbBytes
                });
                if (response.ok) {
                    showToast(ban ? 'Node revoked (banned)' : 'Node active (unbanned)');
                    fetchData();
                } else {
                    const text = await response.text();
                    showToast('Action failed: ' + text, 'error');
                }
            } catch (err) {
                showToast('Network error: ' + err.message, 'error');
            }
        }

        async function generateToken(e) {
            e.preventDefault();
            const role = document.getElementById('token-role').value;
            const ttl = parseInt(document.getElementById('token-ttl').value);
            const maxUsages = parseInt(document.getElementById('token-usages').value);
            const desc = document.getElementById('token-desc').value;

            const res = await apiCall('/admin/bootstrap-tokens', 'POST', {
                role: role,
                ttl_hours: ttl,
                max_usages: maxUsages,
                description: desc
            });

            if (res) {
                showToast('Token generated successfully');
                document.getElementById('token-desc').value = '';
                alert('Bootstrap Token Generated!\n\nToken Value: ' + res.token + '\n\nCopy this value now. It will not be shown again!');
                fetchData();
            }
        }

        async function savePolicy() {
            const yamlContent = document.getElementById('policy-yaml').value;
            const encoder = new TextEncoder();
            const yamlBytes = encoder.encode(yamlContent);
            
            const lenBytes = writeVarint(yamlBytes.length);
            const pbBytes = new Uint8Array(1 + lenBytes.length + yamlBytes.length);
            pbBytes[0] = 0x0a;
            pbBytes.set(lenBytes, 1);
            pbBytes.set(yamlBytes, 1 + lenBytes.length);

            const headers = {};
            if (adminToken) {
                headers['Authorization'] = 'Bearer ' + adminToken;
            }
            headers['Content-Type'] = 'application/x-protobuf';

            try {
                const response = await fetch('/policies', {
                    method: 'POST',
                    headers: headers,
                    body: pbBytes
                });
                if (response.ok) {
                    showToast('Mesh policy updated and applied');
                    delete document.getElementById('policy-yaml').dataset.edited;
                    fetchData();
                } else {
                    const text = await response.text();
                    showToast('Failed to save policy: ' + text, 'error');
                }
            } catch (err) {
                showToast('Network error: ' + err.message, 'error');
            }
        }

        // Initial fetch and poll loop
        async function poll() {
            await fetchData();
            setTimeout(poll, 5000);
        }
        poll();
    </script>
</body>
</html>
`
