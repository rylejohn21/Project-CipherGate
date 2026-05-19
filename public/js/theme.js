// ============================================================================
// CIPHERGATE: Theme Toggle JavaScript
// Feature 14: Day/Night Mode Implementation
// ============================================================================

/**
 * Initialize theme on page load
 * Feature 14: Restore user's theme preference from localStorage
 */
document.addEventListener('DOMContentLoaded', function() {
  const themeToggle = document.getElementById('themeToggle');
  const savedTheme = localStorage.getItem('theme') || 'dark';
  
  // Apply saved theme
  if (savedTheme === 'light') {
    document.body.classList.add('light-mode');
    themeToggle.textContent = '☀️';
  } else {
    document.body.classList.remove('light-mode');
    themeToggle.textContent = '🌙';
  }
  
  // Add click listener for theme toggle button
  if (themeToggle) {
    themeToggle.addEventListener('click', toggleTheme);
  }
});

/**
 * Feature 14: Toggle between dark and light modes
 * Saves preference to localStorage for persistence
 */
function toggleTheme() {
  const themeToggle = document.getElementById('themeToggle');
  const body = document.body;
  
  // Toggle light-mode class
  body.classList.toggle('light-mode');
  
  // Update theme toggle button icon
  if (body.classList.contains('light-mode')) {
    themeToggle.textContent = '☀️';
    localStorage.setItem('theme', 'light');
  } else {
    themeToggle.textContent = '🌙';
    localStorage.setItem('theme', 'dark');
  }
}
