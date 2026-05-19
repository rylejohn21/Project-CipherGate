// Shared API helper for both Express-served pages and VS Code Live Server.
(function () {
  const API_PORT = '3000';
  const localHosts = ['localhost', '127.0.0.1'];
  const configuredApiBase = (window.CIPHERGATE_API_BASE || '').replace(/\/$/, '');
  const isLocalFrontend = localHosts.includes(window.location.hostname);
  const apiOrigin = `${window.location.protocol}//${window.location.hostname}:${API_PORT}`;
  const apiBase = configuredApiBase || (isLocalFrontend && window.location.port !== API_PORT ? apiOrigin : '');

  window.apiFetch = function apiFetch(path, options = {}) {
    return fetch(`${apiBase}${path}`, {
      ...options,
      credentials: options.credentials || 'include'
    });
  };
})();
