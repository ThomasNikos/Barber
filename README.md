# Barber — business plan calculator

Interactive cost and profit model for the barbershop in Kalamata (75 m², 4–5 chairs, coffee corner).
It's a single static page for GitHub Pages, and it's protected by a password.

## Layout

- `src/app.html` is the whole app (HTML/CSS/JS, no dependencies). Open it directly during development.
- `build.mjs` encrypts `src/app.html` with AES-256-GCM, using a key derived from the password with PBKDF2-SHA256 at 600k iterations. It writes the result to `docs/index.html`.
- `docs/` is the folder GitHub Pages serves. Set Pages to "Deploy from branch → main → /docs".

## Build

```bash
BARBER_PASSWORD='your-password' node build.mjs
```

To change the password, rebuild with a new one and push. Anyone who ticked "remember me" will be asked to log in again.

## Preview locally

```bash
python3 -m http.server 8899 --bind 127.0.0.1
# app without password:  http://127.0.0.1:8899/src/app.html
# published version:     http://127.0.0.1:8899/docs/
```

## Notes

- The published `docs/index.html` contains only ciphertext. The app is unreadable without the password.
- If the repository is public, `src/app.html` (code plus default estimates) is visible on GitHub. To hide it, either keep `src/` out of the public repo or use a private repo, which needs GitHub Pro for Pages.
- Edits are shared between all partners through Supabase (project `barber`, schema in `supabase/schema.sql`). The browser encrypts the state with a key derived from the password before upload, so the database stores only ciphertext. Writes need a token derived from the same password.
- After changing the password, run the SQL statement that `build.mjs` prints, so saving keeps working. The first person to open the new version re-uploads the data encrypted with the new password.
- The **Κλείδωμα** (lock) button makes the numbers read-only for everyone until someone unlocks them.
- All default figures are estimates as of November 2026. Check them with the accountant, especially the employer contribution rate (21.79%), VAT and the legal set-up for chair rental.

## License

Proprietary. All rights reserved. See `LICENSE`.
