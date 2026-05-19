// ============================================================================
// CIPHERGATE: Admin Dashboard JavaScript
// Feature 4: RBAC - Only admins can access this dashboard
// Feature 3, 4, 6: Admin management functions
// ============================================================================

/**
 * Initialize admin dashboard on page load
 */
document.addEventListener('DOMContentLoaded', function() {
  checkAdminAuthentication();
  loadDashboardOverview();
  
  // Activate first section by default
  const firstMenuItem = document.querySelector('.menu-item');
  if (firstMenuItem) {
    firstMenuItem.click();
  }
});

/**
 * Feature 4 (RBAC): Check if user is admin
 * Redirects to user dashboard if regular user
 * Redirects to login if not authenticated
 */
async function checkAdminAuthentication() {
  try {
    const response = await apiFetch('/api/current-user');
    
    if (!response.ok) {
      // Not authenticated - redirect to login
      window.location.href = '/login.html';
      return;
    }
    
    const user = await response.json();
    
    // Feature 4: Check if user is admin
    if (user.role !== 'admin') {
      // Regular user trying to access admin panel
      window.location.href = '/user_dashboard.html';
      return;
    }
    
    // Display admin name in navbar
    document.getElementById('userDisplay').textContent = user.username + ' (Admin)';
    
  } catch (error) {
    console.error('Authentication check error:', error);
    window.location.href = '/login.html';
  }
}

/**
 * Feature 4: Load dashboard overview statistics
 */
async function loadDashboardOverview() {
  try {
    // Load users
    const usersResponse = await apiFetch('/api/users');
    const users = await usersResponse.json();
    
    // Load logs
    const logsResponse = await apiFetch('/api/logs');
    const logs = await logsResponse.json();

    if (!usersResponse.ok || !Array.isArray(users)) {
      console.error('Unexpected users response:', users);
      return;
    }

    if (!logsResponse.ok || !Array.isArray(logs)) {
      console.error('Unexpected logs response:', logs);
      return;
    }
    
    // Calculate statistics
    const lockedAccounts = users.filter(u => u.lockout_until && new Date(u.lockout_until) > new Date()).length;
    
    // Update stats in dashboard
    document.getElementById('totalUsers').textContent = users.length;
    document.getElementById('lockedAccounts').textContent = lockedAccounts;
    document.getElementById('recentActivities').textContent = logs.length;
    
  } catch (error) {
    console.error('Error loading dashboard overview:', error);
  }
}

/**
 * Feature 4: Load all users for management
 * Admin can see all users and their lockout status
 */
async function loadUsers() {
  try {
    const response = await apiFetch('/api/users');
    const tableBody = document.getElementById('usersTableBody');
    
    if (!response.ok) {
      console.error('Error loading users');
      tableBody.innerHTML = '<tr><td colspan="7">Unable to load users</td></tr>';
      return;
    }
    
    const users = await response.json();

    if (!Array.isArray(users)) {
      console.error('Unexpected users payload:', users);
      tableBody.innerHTML = '<tr><td colspan="7">Unexpected server response</td></tr>';
      return;
    }
    
    if (users.length === 0) {
      tableBody.innerHTML = '<tr><td colspan="7">No users found</td></tr>';
      return;
    }
    
    // Build table rows
    tableBody.innerHTML = users.map(user => {
      const isLocked = user.lockout_until && new Date(user.lockout_until) > new Date();
      const lockoutStatus = isLocked ? `🔒 Until ${new Date(user.lockout_until).toLocaleTimeString()}` : '🔓 Active';
      
      return `
        <tr>
          <td><strong>${user.username}</strong></td>
          <td>${user.role === 'admin' ? '👨‍💼 Admin' : '👤 User'}</td>
          <td>${user.attempts}</td>
          <td>${user.failed_login_count || 0}</td>
          <td>${lockoutStatus}</td>
          <td>${new Date(user.created_at).toLocaleDateString()}</td>
          <td>
            ${isLocked ? `<button onclick="unlockAccount('${user.username}')" class="btn-action">Unlock</button>` : '-'}
          </td>
        </tr>
      `;
    }).join('');
    
  } catch (error) {
    console.error('Error loading users:', error);
  }
}

/**
 * Feature 3: Unlock a locked account
 * Feature 4: Admin only function
 */
async function unlockAccount(username) {
  if (!confirm(`Are you sure you want to unlock ${username}'s account?`)) {
    return;
  }
  
  try {
    const response = await apiFetch(`/api/user/${username}/unlock`, {
      method: 'POST'
    });
    
    if (!response.ok) {
      alert('Error unlocking account');
      return;
    }
    
    alert(`Account ${username} has been unlocked`);
    
    // Reload users table
    loadUsers();
    
  } catch (error) {
    console.error('Error unlocking account:', error);
    alert('Server error');
  }
}

/**
 * Filter users table by search term
 */
function filterUsers() {
  const searchTerm = document.getElementById('userSearch').value.toLowerCase();
  const tableRows = document.querySelectorAll('#usersTableBody tr');
  
  tableRows.forEach(row => {
    const username = row.querySelector('td strong').textContent.toLowerCase();
    if (username.includes(searchTerm)) {
      row.style.display = '';
    } else {
      row.style.display = 'none';
    }
  });
}

/**
 * Feature 4: Load activity logs
 * Admin can see all user activities with IP tracking
 */
async function loadLogs() {
  try {
    const response = await apiFetch('/api/logs');
    const tableBody = document.getElementById('logsTableBody');
    
    if (!response.ok) {
      console.error('Error loading logs');
      tableBody.innerHTML = '<tr><td colspan="5">Unable to load activity logs</td></tr>';
      return;
    }
    
    const logs = await response.json();

    if (!Array.isArray(logs)) {
      console.error('Unexpected logs payload:', logs);
      tableBody.innerHTML = '<tr><td colspan="5">Unexpected server response</td></tr>';
      return;
    }
    
    if (logs.length === 0) {
      tableBody.innerHTML = '<tr><td colspan="5">No activities logged</td></tr>';
      return;
    }
    
    // Build table rows with color coding
    tableBody.innerHTML = logs.map(log => {
      const actionEmoji = getActionEmoji(log.action);
      const timestamp = new Date(log.timestamp).toLocaleString();
      
      return `
        <tr>
          <td>${timestamp}</td>
          <td><strong>${log.username}</strong></td>
          <td>${actionEmoji} ${log.action}</td>
          <td>${log.details || '-'}</td>
          <td><code>${log.ip_address}</code></td>
        </tr>
      `;
    }).join('');
    
  } catch (error) {
    console.error('Error loading logs:', error);
  }
}

/**
 * Get emoji based on action type for visual clarity
 */
function getActionEmoji(action) {
  const emojiMap = {
    'LOGIN_SUCCESS': '✅',
    'LOGIN_FAILURE': '❌',
    'LOGIN_ATTEMPT_LOCKED': '🚫',
    'LOGIN_CAPTCHA_FAILURE': '❌',
    'LOGIN_SECURITY_FAILURE': '⚠️',
    'PASSWORD_CHANGED': '🔐',
    'PASSWORD_CHANGE_FAILURE': '❌',
    'LOGOUT': '🚪',
    'VIEW_LOGS': '📋',
    'VIEW_ALL_USERS': '👥',
    'VIEW_USER_LOGS': '📋',
    'UNLOCK_ACCOUNT': '🔓',
    'UNAUTHORIZED_ACCESS': '🚫',
    'USER_REGISTRATION': '✍️'
  };
  
  return emojiMap[action] || '📝';
}

/**
 * Filter logs by search term and action
 */
function filterLogs() {
  const searchTerm = document.getElementById('logSearch').value.toLowerCase();
  const actionFilter = document.getElementById('actionFilter').value;
  const tableRows = document.querySelectorAll('#logsTableBody tr');
  
  tableRows.forEach(row => {
    const cells = row.querySelectorAll('td');
    const username = cells[1].textContent.toLowerCase();
    const action = cells[2].textContent.toLowerCase();
    const details = cells[3].textContent.toLowerCase();
    
    const matchesSearch = username.includes(searchTerm) || 
                         action.includes(searchTerm) || 
                         details.includes(searchTerm);
    
    const matchesAction = !actionFilter || action.includes(actionFilter);
    
    if (matchesSearch && matchesAction) {
      row.style.display = '';
    } else {
      row.style.display = 'none';
    }
  });
}

/**
 * Show/hide dashboard sections
 */
function showSection(sectionId, menuButton = null) {
  // Hide all sections
  const sections = document.querySelectorAll('.dashboard-section');
  sections.forEach(section => {
    section.classList.remove('active');
  });
  
  // Hide all menu items active state
  const menuItems = document.querySelectorAll('.menu-item');
  menuItems.forEach(item => {
    item.classList.remove('active');
  });
  
  // Show selected section
  const selectedSection = document.getElementById(sectionId);
  if (selectedSection) {
    selectedSection.classList.add('active');
  }
  
  // Mark menu item as active
  if (menuButton) {
    menuButton.classList.add('active');
  }
  
  // Load data for specific sections
  if (sectionId === 'users') {
    loadUsers();
  } else if (sectionId === 'logs') {
    loadLogs();
  }
}

/**
 * Feature 6: Logout and destroy session
 */
async function logout() {
  try {
    const response = await apiFetch('/api/logout', {
      method: 'POST'
    });
    
    if (response.ok) {
      // Session destroyed - redirect to login
      window.location.href = '/login.html';
    }
  } catch (error) {
    console.error('Logout error:', error);
    alert('Error logging out. Please try again.');
  }
}
