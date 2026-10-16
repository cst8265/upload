<?php declare(strict_types=1); ?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>CST8265 · File Upload Lab</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet"
          integrity="sha384-QWTKZyjpPEjISv5WaRU9OFeRpok6YctnYmDr5pNlyT2bRjXh0JMhjY6hW+ALEwIH" crossorigin="anonymous">
</head>
<body class="bg-body-tertiary">
<main class="container py-5">
    <h1 class="mb-1">File Upload Lab</h1>
    <p class="text-secondary mb-4">CST8265 Web Security · Compare an insecure and a hardened image upload form.</p>

    <div class="row g-4">
        <div class="col-md-6">
            <div class="card h-100 border-danger">
                <div class="card-body">
                    <h2 class="h4 card-title text-danger">Insecure version</h2>
                    <p class="card-text">Trusts the browser, keeps the original filename and saves files inside the web root.
                        Find and exploit its weaknesses.</p>
                    <a href="/insecure/" class="btn btn-danger">Open insecure form</a>
                </div>
            </div>
        </div>
        <div class="col-md-6">
            <div class="card h-100 border-success">
                <div class="card-body">
                    <h2 class="h4 card-title text-success">Secure version</h2>
                    <p class="card-text">Validates content server-side, re-encodes images, renames files and stores them
                        outside the web root.</p>
                    <a href="/secure/" class="btn btn-success">Open secure form</a>
                </div>
            </div>
        </div>
    </div>

    <div class="alert alert-warning mt-4 mb-0">
        <strong>Lab use only.</strong> The insecure version is intentionally vulnerable. Run it on
        <code>localhost</code> only and never deploy it to a public server.
    </div>
</main>
</body>
</html>
