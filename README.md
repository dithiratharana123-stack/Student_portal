# KCSS Science Society Student Portal — Python 3

Python 3-only edition of the KCSS Science Society portal. It uses the Python standard library and SQLite, so Node.js/npm is not required.

## Run

### Windows
Double-click `run_windows.bat`, or:

```bash
py -3 server.py
```

### Linux / macOS

```bash
python3 server.py
```

Then open `http://127.0.0.1:3000`.

Default admin login:
- Email: `admin@kcss.local`
- Password: `ChangeMe123!`

Change these before real deployment with environment variables / `.env` values.

## Included features

- Premium blue/white glassmorphism animated login screen
- Responsive desktop/mobile layout
- KCSS Science Society branding without the school crest/logo
- Student/admin role separation
- SQLite database created automatically in `data/kcss.sqlite`
- Secure password hashing with PBKDF2-HMAC-SHA256
- Admin dashboard
- Create, update and delete student accounts
- Student profile fields: name, class, stream, phone, email
- Grade 12 and Grade 13 marks
- Test / subject / term / mark / maximum mark records
- Add/update marks from the student's admin detail page
- Student mark sheet
- Animated subject performance analysis
- Student self-service profile updates
- Google, Facebook and Apple OAuth entry points + environment configuration hooks
- `/admin/student/<id>/analysis` JSON analysis endpoint
- Student self-registration at `/register`
- Separate Student Login and Admin Login modes
- Grade-wise school rank and Z-score (based on each student's average percentage within that grade)

## OAuth

The social-login buttons are shown and routed when their provider client IDs are configured. Add provider credentials to your environment and set each provider's callback URL to:

- Google: `http://127.0.0.1:3000/auth/google/callback`
- Facebook: `http://127.0.0.1:3000/auth/facebook/callback`
- Apple: `http://127.0.0.1:3000/auth/apple/callback`

This Python standard-library build keeps the OAuth provider hooks isolated so the local portal itself never depends on Node/npm packages.

## Files

- `server.py` — full Python web server, authentication, SQLite database and routes
- `assets/kcss-login-reference.png` — supplied reference image
- `assets/kcss-login-interface-reference.png` — supplied reference image
- `data/kcss.sqlite` — created automatically on first start


## Latest portal fixes
- Student portal now always displays six term sheets: Grade 12 Term 1/2/3 and Grade 13 Term 1/2/3. Empty terms remain visible until an admin publishes marks.
- Each term sheet includes average, best score, readiness estimate, likely grade zone, and a clearly labelled portal-only A/L readiness estimate.
- School rank and Z-score are recalculated grade-by-grade after mark changes.
- Admin student records now have a visible Back to Admin Dashboard button.
- Every saved mark has an Edit action that loads the existing record back into the form; saving updates the same database row rather than creating a duplicate.
- Admin can also delete an individual mark record.
