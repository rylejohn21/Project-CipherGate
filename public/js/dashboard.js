// ============================================================================
// CIPHERGATE: User Dashboard JavaScript
// Feature 4, 6: User can only view their own profile
// Features: 1, 6, 12
// ============================================================================

/**
 * Initialize user dashboard on page load
 */
document.addEventListener('DOMContentLoaded', function() {
  checkAuthentication();
  loadUserProfile();
  
  // Setup form listeners
  const changePasswordForm = document.getElementById('changePasswordForm');
  if (changePasswordForm) {
    changePasswordForm.addEventListener('submit', handleChangePassword);
  }
});

/**
 * Feature 6: Check if user is authenticated
 * Redirects to login if not authenticated
 */
async function checkAuthentication() {
  try {
    const response = await apiFetch('/api/current-user');
    
    if (!response.ok) {
      // Not authenticated - redirect to login
      window.location.href = '/login.html';
      return;
    }
    
    const user = await response.json();
    
    // Feature 4: Only users (not admins) should access user dashboard
    if (user.role === 'admin') {
      window.location.href = '/admin_dashboard.html';
      return;
    }
    
    // Display user info in navbar
    document.getElementById('userDisplay').textContent = user.username;
    
  } catch (error) {
    console.error('Authentication check error:', error);
    window.location.href = '/login.html';
  }
}

/**
 * Feature 4: Load user profile information
 * User can only see their own profile (enforced on server)
 */
async function loadUserProfile() {
  try {
    // Get current user first
    const currentUserResponse = await apiFetch('/api/current-user');
    if (!currentUserResponse.ok) return;
    
    const currentUser = await currentUserResponse.json();
    
    // Feature 4: Fetch user's own profile only
    const response = await apiFetch(`/api/user/${currentUser.username}`);
    
    if (!response.ok) {
      console.error('Error loading profile');
      return;
    }
    
    const user = await response.json();
    
    // Display profile information
    document.getElementById('profileUsername').textContent = user.username;
    document.getElementById('profileRole').textContent = user.role === 'user' ? '👤 Regular User' : '👨‍💼 Administrator';
    document.getElementById('displayUsername').textContent = user.username;
    document.getElementById('displayRole').textContent = user.role === 'user' ? 'Standard User' : 'Administrator';
    
  } catch (error) {
    console.error('Error loading profile:', error);
  }
}

/**
 * Feature 1 & 12: Handle password change
 * New password is hashed on server using bcryptjs
 */
async function handleChangePassword(e) {
  e.preventDefault();
  
  const currentPassword = document.getElementById('currentPassword').value;
  const newPassword = document.getElementById('newPassword').value;
  const passwordError = document.getElementById('passwordError');
  const passwordSuccess = document.getElementById('passwordSuccess');
  
  // Clear messages
  passwordError.style.display = 'none';
  passwordSuccess.style.display = 'none';
  
  // Validate password strength
  const passwordRegex = /^(?=.*[A-Z])(?=.*\d)[a-zA-Z\d@$!%*?&]{8,}$/;
  if (!passwordRegex.test(newPassword)) {
    passwordError.textContent = '❌ New password must be at least 8 characters with 1 uppercase letter and 1 number';
    passwordError.style.display = 'block';
    return;
  }
  
  try {
    const response = await apiFetch('/api/change-password', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        currentPassword,
        newPassword
      })
    });
    
    const data = await response.json();
    
    if (!response.ok) {
      passwordError.textContent = '❌ ' + data.message;
      passwordError.style.display = 'block';
      return;
    }
    
    // Feature 1 & 12: Password successfully updated
    passwordSuccess.textContent = '✅ Password changed successfully! Your new password is now secured with bcrypt encryption.';
    passwordSuccess.style.display = 'block';
    
    // Clear form
    document.getElementById('changePasswordForm').reset();
    
    // Hide success message after 3 seconds
    setTimeout(() => {
      passwordSuccess.style.display = 'none';
    }, 3000);
    
  } catch (error) {
    console.error('Error changing password:', error);
    passwordError.textContent = '❌ Server error. Please try again.';
    passwordError.style.display = 'block';
  }
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

/**
 * Toggle password visibility
 */
function togglePasswordVisibility(inputId) {
  const input = document.getElementById(inputId);
  if (input.type === 'password') {
    input.type = 'text';
  } else {
    input.type = 'password';
  }
}
