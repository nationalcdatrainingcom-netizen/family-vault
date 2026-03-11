# Family Vault

A secure, multi-user password manager for families. Built with Node.js/Express, deployed on Render.

## Features
- Individual logins for each family member
- AES-encrypted vault entries (passwords, PINs, notes)
- Bcrypt-hashed login passwords
- Admin view: see all family members' entries
- Admin tools: add/remove members, reset passwords, change family access code
- Backup/export to JSON

---

## Deploy to Render

### 1. Push to GitHub
Create a new repo at github.com (e.g. `family-vault`) under your `nationalcdatrainingcom-netizen` org and push all these files.

### 2. Create a Render Web Service
- Go to render.com → New → Web Service
- Connect your GitHub repo
- **Build Command:** `npm install`
- **Start Command:** `node server.js`
- **Instance type:** Free (or Starter for persistence)

### 3. Add a Persistent Disk (IMPORTANT)
Without a disk, data resets every deploy. On Render:
- Go to your service → Disks → Add Disk
- **Mount Path:** `/opt/render/project/data`
- **Size:** 1 GB (more than enough)

### 4. Set Environment Variables
In Render → Environment, add these:

| Key | Value |
|-----|-------|
| `VAULT_SECRET` | A long random string (e.g. `MyFamily$ecret!2024XyZ`) — this encrypts all vault entries |
| `FAMILY_CODE` | Your family registration code (e.g. `WardlawFamily2024`) |
| `DATA_DIR` | `/opt/render/project/data` |
| `NODE_ENV` | `production` |

> ⚠️ **Keep VAULT_SECRET safe and never change it** after entries are saved — changing it will make existing entries unreadable.

---

## First-Time Setup
1. Open your Render URL
2. Click "Create account" — the **first account registered becomes admin**
3. Log in and go to ⚙️ Admin to see your Family Access Code
4. Share the URL and code with family members so they can register

## Security Notes
- Login passwords are hashed with bcrypt (never stored as plain text)
- Vault entries are AES-256 encrypted on the server
- Sessions are httpOnly cookies, secured on HTTPS
- Render provides free HTTPS automatically
- For maximum security, use a strong `VAULT_SECRET` env variable
