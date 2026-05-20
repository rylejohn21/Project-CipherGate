document.addEventListener('DOMContentLoaded', function () {
  const otpForm = document.getElementById('otpFormElement');
  const resendButton = document.getElementById('resendOtpButton');
  const backButton = document.getElementById('backToLoginButton');
  const otpInput = document.getElementById('otpCode');

  if (otpForm) {
    otpForm.addEventListener('submit', handleOtpVerify);
  }

  if (resendButton) {
    resendButton.addEventListener('click', handleOtpResend);
  }

  if (backButton) {
    backButton.addEventListener('click', function () {
      window.location.href = '/login.html';
    });
  }

  if (otpInput) {
    otpInput.addEventListener('input', function () {
      otpInput.value = otpInput.value.replace(/\D/g, '').slice(0, 6);
    });
  }

  loadOtpStatus();
});

function showOtpMessage(type, message) {
  const messageIds = ['otpMessage', 'otpSuccess', 'otpError'];

  messageIds.forEach(id => {
    const element = document.getElementById(id);
    if (element) {
      element.style.display = 'none';
      element.textContent = '';
    }
  });

  const targetId = type === 'success' ? 'otpSuccess' : type === 'error' ? 'otpError' : 'otpMessage';
  const target = document.getElementById(targetId);

  if (target) {
    target.textContent = message;
    target.style.display = 'block';
  }
}

async function loadOtpStatus() {
  try {
    const response = await apiFetch('/api/login-otp/status', {
      cache: 'no-store'
    });
    const data = await response.json();

    if (!response.ok) {
      showOtpMessage('error', data.message || 'Please log in again to request an OTP.');
      setTimeout(() => {
        window.location.href = '/login.html';
      }, 1800);
      return;
    }

    showOtpMessage('info', `An OTP was sent to ${data.email}.`);
  } catch (error) {
    console.error('OTP status error:', error);
    showOtpMessage('error', 'Unable to load OTP status. Please log in again.');
  }
}

async function handleOtpVerify(e) {
  e.preventDefault();

  const otpCode = document.getElementById('otpCode').value.trim();

  if (!/^\d{6}$/.test(otpCode)) {
    showOtpMessage('error', 'Enter the 6-digit OTP from your Gmail/email.');
    return;
  }

  try {
    const response = await apiFetch('/api/login-otp/verify', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ otpCode })
    });
    const data = await response.json();

    if (!response.ok) {
      showOtpMessage('error', data.message || 'Invalid OTP code.');
      return;
    }

    showOtpMessage('success', data.message || 'OTP verified.');

    if (data.redirect) {
      window.location.href = data.redirect;
    }
  } catch (error) {
    console.error('OTP verification error:', error);
    showOtpMessage('error', 'Server error. Please try again.');
  }
}

async function handleOtpResend() {
  const resendButton = document.getElementById('resendOtpButton');

  try {
    if (resendButton) {
      resendButton.disabled = true;
      resendButton.textContent = 'Sending...';
    }

    const response = await apiFetch('/api/login-otp/resend', {
      method: 'POST'
    });
    const data = await response.json();

    if (!response.ok) {
      showOtpMessage('error', data.message || 'Unable to resend OTP.');
      return;
    }

    showOtpMessage('info', data.message || `A new OTP was sent to ${data.email}.`);
    document.getElementById('otpCode').value = '';
  } catch (error) {
    console.error('OTP resend error:', error);
    showOtpMessage('error', 'Unable to resend OTP right now.');
  } finally {
    if (resendButton) {
      resendButton.disabled = false;
      resendButton.textContent = 'Resend OTP';
    }
  }
}
