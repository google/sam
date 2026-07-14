document.addEventListener('DOMContentLoaded', () => {
    // Navigation handling
    const navItems = document.querySelectorAll('.nav-item');
    const viewSections = document.querySelectorAll('.view-section');

    navItems.forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            const target = e.currentTarget.getAttribute('data-target');
            
            // Update active states
            navItems.forEach(n => n.classList.remove('active'));
            e.currentTarget.classList.add('active');
            
            viewSections.forEach(v => v.classList.remove('active'));
            document.getElementById(`view-${target}`).classList.add('active');
            
            // Optionally fetch data specifically for that view if needed
            // Currently, loadData() fetches everything from the status endpoint.
        });
    });

    // Check auth status on load
    checkAuthAndLoad();
});

async function checkAuthAndLoad() {
    try {
        const infoResp = await fetch('/console/info');
        if (infoResp.ok) {
            const info = await infoResp.json();
            const ssoGroup = document.getElementById('sso-login-group');
            if (ssoGroup) {
                ssoGroup.style.display = info.oidc_enabled ? 'block' : 'none';
            }
        }
    } catch (e) {
        console.error("Failed to load console auth info:", e);
    }

    try {
        await loadData();
        document.getElementById('landing-page').classList.remove('active');
        document.getElementById('app-container').style.display = 'flex';
    } catch (error) {
        document.getElementById('landing-page').classList.add('active');
        document.getElementById('app-container').style.display = 'none';
    }
}

window.redirectToSSO = function() {
    window.location.href = '/auth/login';
};

window.loginOIDC = function() {
    const token = document.getElementById('oidc-token-input').value.trim();
    if (token) {
        localStorage.setItem('sam_admin_token', token);
        document.getElementById('landing-page').classList.remove('active');
        document.getElementById('app-container').style.display = 'flex';
        loadData();
    }
};

function getAdminToken() {
    return localStorage.getItem('sam_admin_token') || '';
}

window.saveAdminToken = function() {
    const val = document.getElementById('admin-token-input').value.trim();
    if (val) {
        localStorage.setItem('sam_admin_token', val);
        document.getElementById('landing-page').classList.remove('active');
        document.getElementById('app-container').style.display = 'flex';
        loadData();
    }
}

function getAuthHeaders() {
    const token = getAdminToken();
    return token ? { 'Authorization': 'Bearer ' + token } : {};
}

async function loadData() {
    try {
        // 1. Fetch user-scoped status
        const response = await fetch('/api/user/status', {
            headers: getAuthHeaders()
        });
        if (response.status === 401 || response.status === 403) {
            localStorage.removeItem('sam_admin_token');
            document.getElementById('landing-page').classList.add('active');
            document.getElementById('app-container').style.display = 'none';
            throw new Error('Unauthorized. Please login again.');
        }
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        let data = await response.json();
        
        const role = data.user ? data.user.role : 'user';
        const userId = data.user ? data.user.id : '';
        
        // Update UI components depending on Role
        updateUIForRole(role, userId);

        // 2. If user is admin, fetch full unfiltered admin status
        if (role === 'admin') {
            const adminResp = await fetch('/api/admin/status', {
                headers: getAuthHeaders()
            });
            if (adminResp.ok) {
                data = await adminResp.json();
            }
        }
        
        // Update Stats
        const usersCount = (data.users && data.users.length) || 0;
        const nodesCount = (data.enrolled_nodes && data.enrolled_nodes.length) || 0;
        const routersCount = (data.active_routers && data.active_routers.length) || 0;
        const reqsCount = (data.enrollment_requests && data.enrollment_requests.length) || 0;
        
        document.getElementById('stat-users').innerText = usersCount;
        document.getElementById('stat-nodes').innerText = nodesCount;
        document.getElementById('stat-routers').innerText = routersCount;
        
        // Count pending
        const pendingCount = (data.enrollment_requests || []).filter(r => r.Status === 0 || r.Status === 'ENROLLMENT_STATUS_PENDING').length;
        document.getElementById('stat-pending').innerText = pendingCount;

        // Render Tables & Grid
        if (role === 'admin') {
            renderUsersTable(data.users || []);
            renderEnrollmentsTable(data.enrollment_requests || []);
        }
        renderNodesTable(data.enrolled_nodes || []);
        renderRoutersTable(data.active_routers || []);
        renderRouterTopography(data.active_routers || []);
        renderBootstrapTokensTable(data.bootstrap_tokens || []);
        
        // Populate policy yaml if empty
        const policyArea = document.getElementById('policy-yaml');
        if (policyArea && !policyArea.value && data.policy_yaml) {
            policyArea.value = data.policy_yaml;
        }

    } catch (error) {
        console.error('Failed to load dashboard data:', error);
        const errMsg = `<tr><td colspan="4" class="text-center" style="color: var(--danger)">Error loading data: ${error.message}</td></tr>`;
        document.getElementById('table-users').innerHTML = errMsg;
        document.getElementById('table-nodes').innerHTML = errMsg;
        document.getElementById('table-enrollments').innerHTML = errMsg;
        document.getElementById('table-routers').innerHTML = errMsg;
        document.getElementById('table-bootstrap').innerHTML = `<tr><td colspan="5" class="text-center" style="color: var(--danger)">Error loading data: ${error.message}</td></tr>`;
        throw error;
    }
}

function renderUsersTable(users) {
    const tbody = document.getElementById('table-users');
    if (users.length === 0) {
        tbody.innerHTML = `<tr><td colspan="4" class="text-center">No users found</td></tr>`;
        return;
    }
    
    tbody.innerHTML = users.map(user => `
        <tr>
            <td><code>${escapeHTML(user.ID)}</code></td>
            <td>${escapeHTML(user.Role)}</td>
            <td>${escapeHTML(user.Name)}</td>
            <td>${escapeHTML(user.Email)}</td>
        </tr>
    `).join('');
}

function renderNodesTable(nodes) {
    const tbody = document.getElementById('table-nodes');
    if (nodes.length === 0) {
        tbody.innerHTML = `<tr><td colspan="4" class="text-center">No enrolled nodes found</td></tr>`;
        return;
    }
    
    tbody.innerHTML = nodes.map(node => `
        <tr>
            <td><code>${escapeHTML(node.PeerID)}</code></td>
            <td>${escapeHTML(node.Role)}</td>
            <td>${escapeHTML(node.OwnerID)}</td>
            <td>
                <div class="actions-cell">
                    <button class="btn btn-sm btn-danger" onclick="revokeDevice('${escapeHTML(node.PeerID)}')">Revoke</button>
                </div>
            </td>
        </tr>
    `).join('');
}

function getStatusBadge(status) {
    if (status === 0 || status === 'ENROLLMENT_STATUS_PENDING') {
        return `<span class="badge badge-pending">Pending</span>`;
    } else if (status === 1 || status === 'ENROLLMENT_STATUS_APPROVED') {
        return `<span class="badge badge-approved">Approved</span>`;
    } else if (status === 2 || status === 'ENROLLMENT_STATUS_REJECTED') {
        return `<span class="badge badge-rejected">Rejected</span>`;
    }
    return `<span class="badge">Unknown</span>`;
}

function renderEnrollmentsTable(reqs) {
    const tbody = document.getElementById('table-enrollments');
    if (reqs.length === 0) {
        tbody.innerHTML = `<tr><td colspan="4" class="text-center">No enrollment requests found</td></tr>`;
        return;
    }
    
    tbody.innerHTML = reqs.map(req => {
        const isPending = req.Status === 0 || req.Status === 'ENROLLMENT_STATUS_PENDING';
        let actions = '';
        if (isPending) {
            actions = `
                <div class="actions-cell">
                    <button class="btn btn-sm btn-success" onclick="approveEnrollment('${escapeHTML(req.ID)}')">Approve</button>
                    <button class="btn btn-sm btn-danger" onclick="rejectEnrollment('${escapeHTML(req.ID)}')">Reject</button>
                </div>
            `;
        }
        return `
        <tr>
            <td><code>${escapeHTML(req.ID)}</code></td>
            <td>${getStatusBadge(req.Status)}</td>
            <td>${escapeHTML(req.CreatedAt)}</td>
            <td>${actions}</td>
        </tr>
        `;
    }).join('');
}

function renderRoutersTable(routers) {
    const tbody = document.getElementById('table-routers');
    if (routers.length === 0) {
        tbody.innerHTML = `<tr><td colspan="3" class="text-center">No active routers found</td></tr>`;
        return;
    }
    
    tbody.innerHTML = routers.map(router => `
        <tr>
            <td><code>${escapeHTML(router.PeerID)}</code></td>
            <td>${router.Addresses ? router.Addresses.map(addr => escapeHTML(addr)).join('<br>') : '-'}</td>
            <td>${escapeHTML(router.ExpiresAt)}</td>
        </tr>
    `).join('');
}

async function actionRequest(url, method = 'POST', body = null) {
    try {
        const options = {
            method,
            headers: getAuthHeaders()
        };
        if (body) {
            options.headers['Content-Type'] = 'application/json';
            options.body = JSON.stringify(body);
        }
        
        const response = await fetch(url, options);
        if (response.status === 401 || response.status === 403) {
            localStorage.removeItem('sam_admin_token');
            document.getElementById('landing-page').classList.add('active');
            document.getElementById('app-container').style.display = 'none';
            throw new Error('Unauthorized. Please login again.');
        }
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        // Return JSON if present, otherwise just true
        const contentType = response.headers.get("content-type");
        if (contentType && contentType.indexOf("application/json") !== -1) {
            return await response.json();
        }
        
        // Refresh data
        loadData();
        return true;
    } catch (error) {
        alert('Action failed: ' + error.message);
        throw error;
    }
}

function approveEnrollment(id) {
    if (confirm('Are you sure you want to approve this enrollment?')) {
        actionRequest(`/api/admin/enrollments/${id}/approve`);
    }
}

function rejectEnrollment(id) {
    if (confirm('Are you sure you want to reject this enrollment?')) {
        actionRequest(`/api/admin/enrollments/${id}/reject`);
    }
}

function revokeDevice(id) {
    if (confirm('Are you sure you want to revoke this device? This will terminate its connection.')) {
        actionRequest(`/api/user/revoke?id=${id}`);
    }
}

window.logout = function() {
    localStorage.removeItem('sam_admin_token');
    window.location.href = '/auth/logout';
};

function updateUIForRole(role, userId) {
    // 1. Update Profile Display
    const profileSpan = document.querySelector('.user-profile span');
    if (profileSpan) {
        profileSpan.innerText = role === 'admin' ? 'Admin' : (userId ? userId.substring(0, 15) + '...' : 'User');
    }
    const avatarDiv = document.querySelector('.user-profile .avatar');
    if (avatarDiv) {
        avatarDiv.innerText = role === 'admin' ? 'A' : 'U';
    }

    // 2. Hide/Show Navigation Options
    const navItems = document.querySelectorAll('.nav-item');
    navItems.forEach(item => {
        const target = item.getAttribute('data-target');
        if (target === 'users' || target === 'enrollments' || target === 'policy') {
            if (role === 'admin') {
                item.style.display = 'flex';
            } else {
                item.style.display = 'none';
                if (item.classList.contains('active')) {
                    switchTab('overview');
                }
            }
        }
    });

    // 3. Hide/Show Form Owner ID input
    const ownerInput = document.getElementById('token-owner');
    if (ownerInput) {
        const group = ownerInput.closest('.input-group');
        if (group) {
            if (role === 'admin') {
                group.style.display = 'flex';
                ownerInput.required = true;
            } else {
                group.style.display = 'none';
                ownerInput.required = false;
                ownerInput.value = userId; // Scoped to user implicitly
            }
        }
    }
    
    // 4. Hide users/pending sections from stats grid for normal users
    const usersCard = document.getElementById('stat-users').closest('.stat-card');
    const pendingCard = document.getElementById('stat-pending').closest('.stat-card');
    if (usersCard && pendingCard) {
        if (role === 'admin') {
            usersCard.style.display = 'block';
            pendingCard.style.display = 'block';
        } else {
            usersCard.style.display = 'none';
            pendingCard.style.display = 'none';
        }
    }
}

function switchTab(target) {
    const navItems = document.querySelectorAll('.nav-item');
    const viewSections = document.querySelectorAll('.view-section');
    navItems.forEach(n => n.classList.remove('active'));
    viewSections.forEach(v => v.classList.remove('active'));

    const activeNav = Array.from(navItems).find(n => n.getAttribute('data-target') === target);
    if (activeNav) activeNav.classList.add('active');

    const activeView = document.getElementById(`view-${target}`);
    if (activeView) activeView.classList.add('active');
}

function renderRouterTopography(routers) {
    const topoList = document.getElementById('router-topography-list');
    topoList.innerHTML = '';
    if (routers.length === 0) {
        topoList.innerHTML = '<div style="grid-column: 1/-1; text-align: center; color: var(--text-secondary); padding: 2rem;">No active routers online in the mesh.</div>';
        return;
    }

    routers.forEach(r => {
        const conns = r.ConnectedPeers || [];
        const dhtSize = r.DHTSize || 0;
        
        // Calculate remaining lease time in seconds
        let elapsed = 0;
        if (r.ExpiresAt) {
            elapsed = Math.max(0, Math.floor((new Date(r.ExpiresAt) - new Date()) / 1000));
        }

        const peersHTML = conns.length === 0
            ? '<li>No connected peers</li>'
            : conns.map(p => `<li>${p.substring(0, 15)}... (${p.substring(p.length - 8)})</li>`).join('');

        topoList.innerHTML += `
            <div class="router-item-card">
                <div class="router-header">
                    <span class="router-peer-id" title="${r.PeerID}">${r.PeerID.substring(0, 12)}...${r.PeerID.substring(r.PeerID.length - 8)}</span>
                    <span class="badge badge-approved">Lease: ${elapsed}s</span>
                </div>
                <div class="router-metrics">
                    <div class="router-metric-item">
                        <div class="router-metric-val">${conns.length}</div>
                        <div style="font-size: 0.7rem; color: var(--text-secondary)">Connections</div>
                    </div>
                    <div class="router-metric-item" style="border-left: 1px solid var(--border-color)">
                        <div class="router-metric-val">${dhtSize}</div>
                        <div style="font-size: 0.7rem; color: var(--text-secondary)">DHT Size</div>
                    </div>
                </div>
                <div style="font-size: 0.8rem; font-weight: 600; color: var(--text-secondary)">Connected Peers:</div>
                <ul class="router-peers-list">${peersHTML}</ul>
            </div>
        `;
    });
}

function renderBootstrapTokensTable(tokens) {
    const tbody = document.getElementById('table-bootstrap');
    if (tokens.length === 0) {
        tbody.innerHTML = `<tr><td colspan="5" class="text-center">No active bootstrap tokens found</td></tr>`;
        return;
    }

    tbody.innerHTML = tokens.map(token => {
        const createdAt = new Date(token.CreatedAt).toLocaleString();
        const expiresAt = token.ExpiresAt && !token.ExpiresAt.startsWith('0001') ? new Date(token.ExpiresAt).toLocaleString() : 'Never';
        return `
            <tr>
                <td><code>${token.ID.substring(0, 8)}...</code></td>
                <td>${token.Role}</td>
                <td><code>${token.OwnerID || '-'}</code></td>
                <td>${token.UsagesCount} / ${token.MaxUsages}</td>
                <td>${expiresAt}</td>
            </tr>
        `;
    }).join('');
}

window.generateBootstrapToken = async function() {
    const role = document.getElementById('token-role').value;
    const owner_id = document.getElementById('token-owner').value;
    const max_usages = parseInt(document.getElementById('token-usages').value, 10);
    const description = document.getElementById('token-desc').value;

    const payload = {
        role,
        owner_id,
        max_usages,
        description
    };

    try {
        const res = await actionRequest('/api/user/bootstrap-tokens', 'POST', payload);
        if (res && res.token) {
            alert('Bootstrap Token Generated Successfully!\n\nToken: ' + res.token + '\n\nCopy this token now. It will not be shown again.');
            document.getElementById('form-generate-token').reset();
            loadData();
        }
    } catch (err) {
        // actionRequest already alerts on failure
    }
};

function writeVarint(value) {
    const bytes = [];
    while (value > 127) {
        bytes.push((value & 127) | 128);
        value >>= 7;
    }
    bytes.push(value);
    return bytes;
}

window.savePolicy = async function() {
    const yamlContent = document.getElementById('policy-yaml').value;
    const encoder = new TextEncoder();
    const yamlBytes = encoder.encode(yamlContent);
    
    const lenBytes = writeVarint(yamlBytes.length);
    const pbBytes = new Uint8Array(1 + lenBytes.length + yamlBytes.length);
    pbBytes[0] = 0x0a; // field tag 1 (YamlContent)
    pbBytes.set(lenBytes, 1);
    pbBytes.set(yamlBytes, 1 + lenBytes.length);

    const headers = getAuthHeaders();
    headers['Content-Type'] = 'application/x-protobuf';

    try {
        const response = await fetch('/api/policies', {
            method: 'POST',
            headers: headers,
            body: pbBytes
        });
        if (response.ok) {
            alert('Mesh policy updated and applied successfully!');
            loadData();
        } else {
            const text = await response.text();
            alert('Failed to save policy: ' + text);
        }
    } catch (err) {
        alert('Network error: ' + err.message);
    }
};

function escapeHTML(str) {
    if (!str) return '-';
    return String(str).replace(/[&<>'"]/g, 
        tag => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[tag] || tag)
    );
}
