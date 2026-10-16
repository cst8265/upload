<?php

/**
 * CST8265 Web Security - SECURE image upload
 *
 * Defences (each maps to a flaw in ../insecure/index.php):
 *   D1  Server-side validation; the accept attribute is only a convenience.
 *   D2  MIME type detected from file content with finfo, checked against an allowlist.
 *   D3  File-size and pixel-dimension limits (stops huge files / decompression bombs).
 *   D4  New random filename; extension chosen by the server from the detected type.
 *   D5  Stored outside the web root and served through image.php (never executed).
 *   D6  All output escaped with htmlspecialchars().
 *   D7  CSRF token on the form; POST/Redirect/GET pattern.
 *   D8  Upload error codes checked; security headers (CSP, nosniff, frame-ancestors).
 *   +   Image is re-encoded with GD, stripping metadata and embedded payloads (polyglots).
 */

declare(strict_types=1);

// ---- Configuration ---------------------------------------------------------
const MAX_BYTES      = 2 * 1024 * 1024;   // 2 MB
const MAX_DIMENSION  = 4000;              // px, width or height
const ALLOWED_TYPES  = [                  // detected MIME => extension we assign
    'image/jpeg' => 'jpg',
    'image/png'  => 'png',
    'image/gif'  => 'gif',
    'image/webp' => 'webp',
];
$storageDir = dirname(__DIR__, 2) . '/storage/uploads';   // D5: outside /public

// ---- Session & headers (D7, D8) -------------------------------------------
session_start([
    'cookie_httponly' => true,
    'cookie_samesite' => 'Strict',
    'use_strict_mode' => true,
]);

header("Content-Security-Policy: default-src 'self'; style-src 'self' https://cdn.jsdelivr.net; "
    . "img-src 'self'; script-src 'none'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'");
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');

$_SESSION['csrf'] ??= bin2hex(random_bytes(32));

function e(string $value): string   // D6
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function flash(string $type, string $text): void
{
    $_SESSION['flash'] = ['type' => $type, 'text' => $text];
    header('Location: ' . strtok($_SERVER['REQUEST_URI'], '?'), true, 303);   // D7: PRG
    exit;
}

/**
 * Validate and store the upload. Returns the stored filename or throws.
 */
function handleUpload(array $file, string $storageDir): string
{
    // D8: check PHP's upload error code first.
    if (!isset($file['error']) || is_array($file['error'])) {
        throw new RuntimeException('Invalid upload.');
    }
    switch ($file['error']) {
        case UPLOAD_ERR_OK:
            break;
        case UPLOAD_ERR_NO_FILE:
            throw new RuntimeException('Please choose a file.');
        case UPLOAD_ERR_INI_SIZE:
        case UPLOAD_ERR_FORM_SIZE:
            throw new RuntimeException('File is too large (max 2 MB).');
        default:
            throw new RuntimeException('Upload failed. Please try again.');
    }

    if (!is_uploaded_file($file['tmp_name'])) {
        throw new RuntimeException('Invalid upload.');
    }

    // D3: size limit (checked on the real file, not the client-reported size).
    $size = filesize($file['tmp_name']);
    if ($size === false || $size === 0 || $size > MAX_BYTES) {
        throw new RuntimeException('File must be between 1 byte and 2 MB.');
    }

    // D2: detect the type from the file's bytes; ignore $_FILES['type'].
    $mime = (new finfo(FILEINFO_MIME_TYPE))->file($file['tmp_name']);
    if (!isset(ALLOWED_TYPES[$mime])) {
        throw new RuntimeException('Only JPEG, PNG, GIF and WebP images are allowed.');
    }

    // D3: confirm it parses as an image and check dimensions before decoding.
    $info = @getimagesize($file['tmp_name']);
    if ($info === false || $info['mime'] !== $mime) {
        throw new RuntimeException('File is not a valid image.');
    }
    [$width, $height] = $info;
    if ($width < 1 || $height < 1 || $width > MAX_DIMENSION || $height > MAX_DIMENSION) {
        throw new RuntimeException('Image dimensions must be at most ' . MAX_DIMENSION . ' px.');
    }

    // Re-encode: decode with GD and write a fresh image. Anything that is not
    // pixel data (EXIF/GPS, comments, appended PHP/HTML) is discarded.
    $image = @imagecreatefromstring((string) file_get_contents($file['tmp_name']));
    if ($image === false) {
        throw new RuntimeException('File is not a valid image.');
    }

    // D4: random, server-generated name + server-chosen extension.
    $ext      = ALLOWED_TYPES[$mime];
    $filename = bin2hex(random_bytes(16)) . '.' . $ext;
    $target   = $storageDir . '/' . $filename;

    if ($ext === 'png' || $ext === 'gif' || $ext === 'webp') {
        imagesavealpha($image, true);
    }
    $ok = match ($ext) {
        'jpg'  => imagejpeg($image, $target, 85),
        'png'  => imagepng($image, $target, 6),
        'gif'  => imagegif($image, $target),    // note: animation is not preserved
        'webp' => imagewebp($image, $target, 85),
    };

    if (!$ok) {
        throw new RuntimeException('Could not save the image.');
    }
    chmod($target, 0644);   // readable, never executable

    return $filename;
}

// ---- Request handling ------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // D7: CSRF check with a constant-time comparison.
    if (!hash_equals($_SESSION['csrf'], (string) ($_POST['csrf'] ?? ''))) {
        flash('danger', 'Your session expired. Please try again.');
    }

    try {
        handleUpload($_FILES['image'] ?? [], $storageDir);
        flash('success', 'Image uploaded and sanitized successfully.');
    } catch (RuntimeException $ex) {
        flash('danger', $ex->getMessage());
    }
}

$flash = $_SESSION['flash'] ?? null;
unset($_SESSION['flash']);

// Gallery: only list files that match our own naming scheme.
$files = array_map('basename', glob($storageDir . '/*.{jpg,png,gif,webp}', GLOB_BRACE) ?: []);
$files = array_values(array_filter($files, fn($f) => preg_match('/^[a-f0-9]{32}\.(jpg|png|gif|webp)$/', $f)));
?>
<!doctype html>
<html lang="en">

<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Secure Image Upload</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet"
        integrity="sha384-QWTKZyjpPEjISv5WaRU9OFeRpok6YctnYmDr5pNlyT2bRjXh0JMhjY6hW+ALEwIH" crossorigin="anonymous">
</head>

<body class="bg-body-tertiary">
    <nav class="navbar bg-success" data-bs-theme="dark">
        <div class="container">
            <a class="navbar-brand" href="/">CST8265 Upload Lab</a>
            <span class="navbar-text">Secure version</span>
        </div>
    </nav>

    <main class="container py-4">
        <?php if ($flash): ?>
            <div class="alert alert-<?= e($flash['type']) ?>"><?= e($flash['text']) ?></div>
        <?php endif; ?>

        <div class="card mb-4">
            <div class="card-body">
                <h1 class="h4 card-title">Upload an image</h1>
                <form method="post" enctype="multipart/form-data">
                    <input type="hidden" name="csrf" value="<?= e($_SESSION['csrf']) ?>">
                    <input type="hidden" name="MAX_FILE_SIZE" value="<?= MAX_BYTES ?>">
                    <div class="mb-3">
                        <label for="image" class="form-label">Choose an image</label>
                        <input class="form-control" type="file" id="image" name="image" required
                            accept="image/jpeg,image/png,image/gif,image/webp">
                        <div class="form-text">JPEG, PNG, GIF or WebP · max 2 MB · max <?= MAX_DIMENSION ?>×<?= MAX_DIMENSION ?> px</div>
                    </div>
                    <button type="submit" class="btn btn-success">Upload</button>
                </form>
            </div>
        </div>

        <h2 class="h5">Uploaded images (<?= count($files) ?>)</h2>
        <?php if (!$files): ?>
            <p class="text-secondary">Nothing uploaded yet.</p>
        <?php else: ?>
            <div class="row row-cols-2 row-cols-md-4 g-3">
                <?php foreach ($files as $f): $url = 'image.php?id=' . rawurlencode($f); ?>
                    <div class="col">
                        <div class="card h-100">
                            <a href="<?= e($url) ?>" target="_blank" rel="noopener">
                                <img src="<?= e($url) ?>" class="card-img-top object-fit-cover" style="height:150px" alt="Uploaded image">
                            </a>
                            <div class="card-body p-2 small text-break font-monospace"><?= e($f) ?></div>
                        </div>
                    </div>
                <?php endforeach; ?>
            </div>
        <?php endif; ?>
    </main>
</body>

</html>