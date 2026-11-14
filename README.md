# Barber — business plan calculator

Interactive cost and profit model for the barbershop in Kalamata (75 m², 4–5 chairs, coffee corner).
It's a single static page for GitHub Pages, and it's protected by a password.

## Layout

- `src/app.html` is the whole app (HTML/CSS/JS, no dependencies). Open it directly during development.
- `build.mjs` encrypts `src/app.html` with AES-256-GCM, using a key derived from the password with PBKDF2-SHA256 at 600k iterations. It writes the result to `docs/index.html`.
- `docs/` is the folder GitHub Pages serves. Set Pages to "Deploy from branch → main → /docs".

## Build and users

Each partner has their own password. Users, passwords and the shared data key live in `.secrets.json`, which is gitignored. Never commit that file.

```bash
node build.mjs                 # rebuild docs/index.html
node build.mjs add "Πάνος"     # add a user with a random password
node build.mjs reset "Θωμάς"   # give a user a new password
```

After `add` or `reset`, run the SQL that the script prints in the Supabase SQL editor. It registers the user's write token, so that user can save and their changes show up in the history.

## Preview locally

```bash
python3 -m http.server 8899 --bind 127.0.0.1
# app without password:  http://127.0.0.1:8899/src/app.html
# published version:     http://127.0.0.1:8899/docs/
```

## Notes

- The published `docs/index.html` contains only ciphertext. The app is unreadable without the password.
- If the repository is public, `src/app.html` (code plus default estimates) is visible on GitHub. To hide it, either keep `src/` out of the public repo or use a private repo, which needs GitHub Pro for Pages.
- Edits are shared between all partners through Supabase (project `barber`, schema in `supabase/schema.sql`). The browser encrypts the state with a key derived from the password before upload, so the database stores only ciphertext. Each user has a personal write token, so the server records who made each change without being able to read the data.
- The **Ιστορικό** tab lists every change (who, when, what) and every login. You can restore any of the last 300 versions.
- The **Κλείδωμα** (lock) button makes the numbers read-only for everyone until someone unlocks them.
- All default figures are estimates as of November 2026. Check them with the accountant, especially the employer contribution rate (21.79%), VAT and the legal set-up for chair rental.

## License

Proprietary. All rights reserved. See `LICENSE`.
