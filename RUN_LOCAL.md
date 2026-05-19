# Run CipherGate Locally

If PowerShell blocks `npm start` with `npm.ps1 cannot be loaded`, use one of these:

```powershell
npm.cmd start
```

Or double-click:

```text
start-ciphergate.cmd
```

Then open:

```text
http://localhost:3000/login.html
```

Login needs Supabase. If login says there is a database connection error, check that `SUPABASE_URL` in `.env` is your real Supabase Project URL and that the Supabase project is active.
