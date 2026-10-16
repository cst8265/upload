<?php
/**
 * CST8265 Web Security - INSECURE image upload
 *
 * WARNING: This file is intentionally vulnerable. It exists so students can
 * identify and exploit common upload flaws. Run on localhost only.
 *
 * Vulnerabilities (compare with ../secure/index.php):
 *   V1  Only "validation" is the HTML accept attribute (client-side, trivially bypassed).
 *   V2  Server trusts the client-supplied MIME type in $_FILES['type'].
 *   V3  No file-size or image-dimension limits.
 *   V4  Original filename is kept -> overwrites, .php uploads, odd characters.
 *   V5  Files are saved inside the public web root -> uploaded scripts can execute (RCE).
 *   V6  Filenames are echoed without escaping -> stored/reflected XSS.
 *   V7  No CSRF token.
 *   V8  Upload errors are ignored and no security headers are sent.
 */

$uploadDir = __DIR__ . '/../uploads/';   // V5: inside the web root
$uploadUrl = '/uploads/';
$message   = null;
$alert     = 'info';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['image'])) {   // V7: no CSRF check
    $file = $_FILES['image'];

    // V2: $_FILES['type'] comes straight from the request - an attacker controls it.
    if (strpos($file['type'], 'image/') === 0) {
        // V4: original, user-controlled filename. V3: no size check. V8: no error check.
        $target = $uploadDir . $file['name'];

        if (move_uploaded_file($file['tmp_name'], $target)) {
            // V6: filename printed without htmlspecialchars()
            $message = "Uploaded <strong>{$file['name']}</strong> successfully!";
            $alert   = 'success';
        } else {
            $message = 'Upload failed.';
            $alert   = 'danger';
        }
    } else {
        $message = "Sorry, {$file['name']} is not an image.";   // V6
        $alert   = 'danger';
    }
}

// List everything in the uploads folder.
$files = array_values(array_filter(scandir($uploadDir), fn($f) => $f[0] !== '.'));
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Insecure Image Upload</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet"
          integrity="sha384-QWTKZyjpPEjISv5WaRU9OFeRpok6YctnYmDr5pNlyT2bRjXh0JMhjY6hW+ALEwIH" crossorigin="anonymous">
</head>
<body class="bg-body-tertiary">
<nav class="navbar bg-danger" data-bs-theme="dark">
    <div class="container">
        <a class="navbar-brand" href="/">CST8265 Upload Lab</a>
        <span class="navbar-text">Insecure version</span>
    </div>
</nav>

<main class="container py-4">
    <div class="alert alert-danger">
        <strong>Intentionally vulnerable.</strong> For classroom use on localhost only.
    </div>

    <?php if ($message): ?>
        <div class="alert alert-<?= $alert ?>"><?= $message /* V6 */ ?></div>
    <?php endif; ?>

    <div class="card mb-4">
        <div class="card-body">
            <h1 class="h4 card-title">Upload an image</h1>
            <!-- V1: accept="image/*" is a UI hint only; it is not a security control. V7: no CSRF token. -->
            <form method="post" enctype="multipart/form-data">
                <div class="mb-3">
                    <label for="image" class="form-label">Choose an image</label>
                    <input class="form-control" type="file" id="image" name="image" accept="image/*" required>
                </div>
                <button type="submit" class="btn btn-danger">Upload</button>
            </form>
        </div>
    </div>

    <h2 class="h5">Uploaded files (<?= count($files) ?>)</h2>
    <?php if (!$files): ?>
        <p class="text-secondary">Nothing uploaded yet.</p>
    <?php else: ?>
        <div class="row row-cols-2 row-cols-md-4 g-3">
            <?php foreach ($files as $f): ?>
                <div class="col">
                    <div class="card h-100">
                        <!-- V6: unescaped filename in attributes and text -->
                        <a href="<?= $uploadUrl . $f ?>" target="_blank">
                            <img src="<?= $uploadUrl . $f ?>" class="card-img-top object-fit-cover" style="height:150px" alt="<?= $f ?>">
                        </a>
                        <div class="card-body p-2 small text-break"><?= $f ?></div>
                    </div>
                </div>
            <?php endforeach; ?>
        </div>
    <?php endif; ?>
</main>
</body>
</html>
