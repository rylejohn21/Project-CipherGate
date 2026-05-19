// ============================================================================
// CIPHERGATE: Authentication JavaScript
// Handles Login, Registration, and CAPTCHA Verification
// Features: 1, 3, 6, 10, 12
// ============================================================================

/**
 * Initialize authentication page on load
 */
document.addEventListener('DOMContentLoaded', function() {
  // Load CAPTCHA on page load
  loadCAPTCHA();
  
  // Setup form event listeners
  const loginForm = document.getElementById('loginFormElement');
  const registerForm = document.getElementById('registerFormElement');
  const forgotPasswordForm = document.getElementById('forgotPasswordFormElement');
  
  if (loginForm) {
    loginForm.addEventListener('submit', handleLogin);
  }
  
  if (registerForm) {
    registerForm.addEventListener('submit', handleRegister);
  }

  if (forgotPasswordForm) {
    forgotPasswordForm.addEventListener('submit', handlePasswordReset);
  }
  
  // Check if user is already logged in
  checkAuthStatus();
});

let captchaLoading = false;
let currentCaptchaToken = '';

/**
 * Feature 10: Load CAPTCHA Challenge
 * Generates a new math CAPTCHA question from server
 */
async function loadCAPTCHA() {
  if (captchaLoading) return;

  const captchaQuestion = document.getElementById('captchaQuestion');
  const captchaAnswer = document.getElementById('captchaAnswer');
  const captchaToken = document.getElementById('captchaToken');
  const captchaRefresh = document.getElementById('captchaRefresh');

  try {
    captchaLoading = true;

    if (captchaQuestion) {
      captchaQuestion.textContent = 'Loading...';
    }

    if (captchaAnswer) {
      captchaAnswer.value = '';
    }

    if (captchaToken) {
      captchaToken.value = '';
    }
    currentCaptchaToken = '';

    if (captchaRefresh) {
      captchaRefresh.disabled = true;
      captchaRefresh.textContent = 'Loading';
    }

    const response = await apiFetch(`/api/captcha?t=${Date.now()}`, {
      cache: 'no-store'
    });

    if (!response.ok) {
      throw new Error(`CAPTCHA request failed with status ${response.status}`);
    }

    const data = await response.json();

    if (!data.question) {
      throw new Error('CAPTCHA response did not include a question');
    }

    if (!data.captchaToken) {
      throw new Error('CAPTCHA response did not include a token');
    }

    if (captchaQuestion) { 
      captchaQuestion.textContent = `Solve: ${data.question} = ?`;
    }

    if (captchaToken) {
      captchaToken.value = data.captchaToken;
    }
    currentCaptchaToken = data.captchaToken;
  } catch (error) {
    console.error('Error loading CAPTCHA:', error);
    if (captchaQuestion) {
      captchaQuestion.textContent = 'CAPTCHA unavailable - run npm start or open localhost:3000';
    }
  } finally {
    captchaLoading = false;

    if (captchaRefresh) {
      captchaRefresh.disabled = false;
      captchaRefresh.textContent = 'New';
    }
  }
}

/**
 * Feature 1, 3, 6, 12: Handle Login Form Submission
 * - Feature 10: Validates CAPTCHA
 * - Feature 1 & 12: User password validated using bcrypt on server
 * - Feature 3: Account lockout check
 * - Feature 6: Creates secure session
 */
async function handleLogin(e) {
  e.preventDefault();
  
  const username = document.getElementById('loginUsername').value;
  const password = document.getElementById('loginPassword').value;
  const captchaAnswer = document.getElementById('captchaAnswer').value;
  const captchaToken = currentCaptchaToken || document.getElementById('captchaToken').value;
  const securityAnswer = document.getElementById('securityAnswer').value;
  const loginError = document.getElementById('loginError');
  
  // Clear previous errors
  loginError.style.display = 'none';
  loginError.textContent = '';

  if (!captchaToken) {
    loginError.textContent = 'CAPTCHA is not ready yet. Click New and try again.';
    loginError.style.display = 'block';
    loadCAPTCHA();
    return;
  }
  
  try {
    const response = await apiFetch('/api/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        username,
        password,
        captchaAnswer,
        captchaToken,
        securityAnswer
      })
    });
    
    const data = await response.json();
    
    if (!response.ok) {
      // Feature 3: Display lockout message if applicable
      if (response.status === 429) {
        loginError.textContent = '🚫 ' + data.message;
      } else {
        loginError.textContent = '❌ ' + data.message;
      }
      loginError.style.display = 'block';
      
      // Reload CAPTCHA on failed attempt
      loadCAPTCHA();
      return;
    }
    
    // Feature 6: Successful login - session created on server
    console.log('Login successful for user:', data.user.username);
    
    // Redirect to appropriate dashboard based on role
    if (data.redirect) {
      window.location.href = data.redirect;
    }
    
  } catch (error) {
    console.error('Login error:', error);
    loginError.textContent = '❌ Server error. Please try again.';
    loginError.style.display = 'block';
  }
}

/**
 * Feature 1 & 12: Handle Registration Form Submission
 * - Password hashed on server using bcryptjs
 * - Security question for account recovery
 */
async function handleRegister(e) {
  e.preventDefault();
  
  const username = document.getElementById('regUsername').value;
  const password = document.getElementById('regPassword').value;
  const email = document.getElementById('regEmail').value;
  const mobileNumber = document.getElementById('regMobileNumber').value;
  const securityQuestion = document.getElementById('securityQuestion').value;
  const securityAnswer = document.getElementById('regSecurityAnswer').value;
  const registerError = document.getElementById('registerError');
  
  // Validate password strength
  const passwordRegex = /^(?=.*[A-Z])(?=.*\d)[a-zA-Z\d@$!%*?&]{8,}$/;
  if (!passwordRegex.test(password)) {
    registerError.textContent = '❌ Password must be at least 8 characters with 1 uppercase letter and 1 number';
    registerError.style.display = 'block';
    return;
  }
  
  // Clear previous errors
  registerError.style.display = 'none';
  registerError.textContent = '';
  
  try {
    const response = await apiFetch('/api/register', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        username,
        password,
        email,
        mobileNumber,
        securityQuestion,
        securityAnswer
      })
    });
    
    const data = await response.json();
    
    if (!response.ok) {
      registerError.textContent = '❌ ' + data.message;
      registerError.style.display = 'block';
      return;
    }
    
    // Registration successful
    alert('✅ Account created successfully! Please login with your credentials.');
    
    // Switch to login form
    switchForm('login');
    
    // Clear registration form
    document.getElementById('registerFormElement').reset();
    
  } catch (error) {
    console.error('Registration error:', error);
    registerError.textContent = '❌ Server error. Please try again.';
    registerError.style.display = 'block';
  }
}

/**
 * Switch between login and registration forms
 */
function switchForm(formType) {
  const loginForm = document.getElementById('loginForm');
  const registerForm = document.getElementById('registerForm');
  const forgotForm = document.getElementById('forgotForm');

  [loginForm, registerForm, forgotForm].forEach(form => {
    if (form) {
      form.classList.remove('active');
    }
  });

  if (formType === 'register') {
    registerForm.classList.add('active');
  } else if (formType === 'forgot') {
    forgotForm.classList.add('active');
  } else {
    loginForm.classList.add('active');
  }
}

function clearForgotPasswordMessages() {
  ['forgotPasswordMessage', 'forgotPasswordError', 'forgotPasswordSuccess'].forEach(id => {
    const element = document.getElementById(id);
    if (element) {
      element.style.display = 'none';
      element.textContent = '';
    }
  });
}

async function requestPasswordResetCode() {
  clearForgotPasswordMessages();

  const username = document.getElementById('forgotUsername').value;
  const recoveryValue = document.getElementById('recoveryValue').value;
  const forgotPasswordMessage = document.getElementById('forgotPasswordMessage');
  const forgotPasswordError = document.getElementById('forgotPasswordError');

  if (!username || !recoveryValue) {
    forgotPasswordError.textContent = 'Error: Username and email are required.';
    forgotPasswordError.style.display = 'block';
    return;
  }

  try {
    const response = await apiFetch('/api/forgot-password/request', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        username,
        recoveryValue
      })
    });

    const data = await response.json();

    if (!response.ok) {
      forgotPasswordError.textContent = 'Error: ' + data.message;
      forgotPasswordError.style.display = 'block';
      return;
    }

    forgotPasswordMessage.textContent = data.message;
    forgotPasswordMessage.style.display = 'block';
  } catch (error) {
    console.error('Password reset code request error:', error);
    forgotPasswordError.textContent = 'Error: Unable to send reset code right now.';
    forgotPasswordError.style.display = 'block';
  }
}

async function handlePasswordReset(e) {
  e.preventDefault();
  clearForgotPasswordMessages();

  const username = document.getElementById('forgotUsername').value;
  const verificationCode = document.getElementById('verificationCode').value;
  const newPassword = document.getElementById('resetNewPassword').value;
  const forgotPasswordError = document.getElementById('forgotPasswordError');
  const forgotPasswordSuccess = document.getElementById('forgotPasswordSuccess');

  const passwordRegex = /^(?=.*[A-Z])(?=.*\d)[a-zA-Z\d@$!%*?&]{8,}$/;
  if (!passwordRegex.test(newPassword)) {
    forgotPasswordError.textContent = 'Error: New password must be at least 8 characters with 1 uppercase letter and 1 number';
    forgotPasswordError.style.display = 'block';
    return;
  }

  try {
    const response = await apiFetch('/api/forgot-password/reset', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        username,
        verificationCode,
        newPassword
      })
    });

    const data = await response.json();

    if (!response.ok) {
      forgotPasswordError.textContent = 'Error: ' + data.message;
      forgotPasswordError.style.display = 'block';
      return;
    }

    forgotPasswordSuccess.textContent = data.message;
    forgotPasswordSuccess.style.display = 'block';
    document.getElementById('forgotPasswordFormElement').reset();
    setTimeout(() => switchForm('login'), 1500);
  } catch (error) {
    console.error('Password reset error:', error);
    forgotPasswordError.textContent = 'Error: Unable to reset password right now.';
    forgotPasswordError.style.display = 'block';
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

/**
 * Feature 6: Check if user is already authenticated
 * Redirects to dashboard if already logged in
 */
async function checkAuthStatus() {
  try {
    const response = await apiFetch('/api/current-user');
    
    if (response.ok) {
      const user = await response.json();
      
      // User already logged in - redirect to dashboard
      if (user.role === 'admin') {
        window.location.href = '/admin_dashboard.html';
      } else {
        window.location.href = '/user_dashboard.html';
      }
    }
  } catch (error) {
    // User not authenticated - allow login/registration
    console.log('Not authenticated - login page available');
  }
}

/**
 * Feature 6: Logout function
 * Destroys session on server
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
