# PeopleDesk

PeopleDesk is a small employee-management website with a shared, server-side employee directory. Every signed-in device reads and updates the same saved employee records. Employee photographs, ID-document images, ID numbers, salary, and contact information are private and are not returned until an administrator signs in.

## Run on your computer

Install Node.js 20 or newer. Open PowerShell in the project folder and run:

```powershell
npm start
```

On first startup, the server prints a one-time admin setup key in its terminal. Open `http://localhost:3000`, enter that key, and create your admin username and password. Employee data is saved in `data\peopledesk.json`; keep a backup of that file.

## Put the shared website online with Render

1. Create a private GitHub repository and upload these project files: `index.html`, `server.js`, `package.json`, `render.yaml`, `.gitignore`, and `README.md`. Do not upload employee-data files or passwords.
2. In Render, create a new **Blueprint** and connect that repository. Render reads `render.yaml`, creates the website, generates an initial-admin setup key, and provisions a persistent disk for employee records.
3. Wait until the service is live, then open **Dashboard → PeopleDesk service → Environment** and copy the value of `ADMIN_SETUP_KEY`. Visit your Render website, paste the key into the first-admin setup form, and create the account. You can use the same admin username and password you used for the browser-only version.
4. After the first admin account has been created, remove `ADMIN_SETUP_KEY` from the Render service's environment settings. Existing admins can still sign in; no further setup key is needed.
5. Sign in on other devices with the same admin username and password. Every authorized login sees the shared employee directory. Keep the Render persistent disk attached; the disk, not a browser, stores employee records.

The Render configuration uses a small paid web service and persistent disk. A public website URL is not available until you connect and deploy the repository to your Render account.

## Local employee-record migration

If the first admin setup is opened in the same browser origin as an older PeopleDesk version, existing locally saved employee records are carried over automatically. Browser-only data cannot be read across different origins (for example, from a `file:///` page after opening a Render website). Before moving an older local-only installation online, open its existing browser page, choose **Download employee backup**, and upload the resulting JSON file in the new website's first-admin setup form. The old admin password is never uploaded; set the shared admin account up again. Other devices will see the migrated records after signing in.

## Security and backup

Passwords are stored as salted PBKDF2 hashes. Sign-in uses an HTTP-only, secure production session cookie with a 12-hour lifetime and login throttling. Employee records require a signed-in admin session. Keep the Render setup key private, remove it after initial setup, limit access to admin credentials, and regularly back up the persistent disk before making major changes.

This lightweight application is designed for a small team. For regulatory or high-sensitivity HR records, use an organization-managed database, encrypted backups, and a production security review before rollout.
