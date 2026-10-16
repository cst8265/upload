# CST8265 – Image Upload Lab

Two versions of the same image upload form: one intentionally insecure, one hardened.

> **Warning:** `public/insecure/` is deliberately vulnerable (remote code execution, XSS).
> Run it on `localhost` only. Never deploy it.

## Requirements

- PHP 8.1+ with the `gd` and `fileinfo` extensions
- Composer

## Run

```bash
composer install     # checks PHP version and extensions
composer serve       # http://localhost:8000
composer reset       # delete all uploaded files
```

| URL | Page |
|---|---|
| `/` | Lab landing page |
| `/insecure/` | Insecure upload form |
| `/secure/` | Secure upload form |

## Structure

```
upload/
├── composer.json
├── public/                  ← web root
│   ├── index.php
│   ├── insecure/index.php   ← vulnerable form
│   ├── secure/index.php     ← hardened form
│   ├── secure/image.php     ← serves stored images safely
│   └── uploads/             ← insecure uploads (inside web root!)
└── storage/uploads/         ← secure uploads (outside web root)
```

## Flaws and fixes

| # | Insecure version | Secure version |
|---|---|---|
| 1 | Relies on `accept="image/*"` (client-side) | All checks happen on the server |
| 2 | Trusts `$_FILES['type']` (client-controlled) | Detects MIME from file bytes with `finfo`, allowlist |
| 3 | No size or dimension limits | 2 MB max, 4000 px max per side |
| 4 | Keeps the original filename | Random name, extension chosen by the server |
| 5 | Saves inside the web root → `.php` files execute | Stored outside the web root, streamed by `image.php` |
| 6 | Echoes filenames unescaped → XSS | `htmlspecialchars()` on all output |
| 7 | No CSRF protection | Session CSRF token + `hash_equals()`, POST/Redirect/GET |
| 8 | Ignores upload errors, no security headers | Checks error codes; CSP, `nosniff`, `frame-ancestors` |
| + | Polyglot files (valid image + PHP) survive | Image re-encoded with GD, stripping metadata and payloads |

## Suggested exercises (insecure version)

1. **Spoofed MIME type** – upload `shell.php` while setting the part's `Content-Type` to `image/png` (`curl http://localhost:8000/insecure/ -F "image=@files/shell.php;type=image/png"`), then browse to `/uploads/shell.php`.
2. **XSS via filename** – upload an image named `<img src=x onerror=alert(1)>.png`.
3. **Overwrite** – upload a different file with the same name as an existing one.
4. **Polyglot** – append PHP code to a real GIF/JPEG (`cat image.gif payload.php > poly.gif.php`).
5. Repeat each attack against `/secure/` and explain which defence stops it.
