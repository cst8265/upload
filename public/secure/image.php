<?php
/**
 * CST8265 Web Security - serves images stored outside the web root.
 *
 * Files are never executed: they are read and streamed with a fixed,
 * server-chosen Content-Type.
 */

declare(strict_types=1);

const TYPES = [
    'jpg'  => 'image/jpeg',
    'png'  => 'image/png',
    'gif'  => 'image/gif',
    'webp' => 'image/webp',
];

$storageDir = realpath(dirname(__DIR__, 2) . '/storage/uploads');
$id         = (string) ($_GET['id'] ?? '');

// Strict allowlist on the name blocks path traversal (../, null bytes, etc.).
if ($storageDir === false || !preg_match('/^[a-f0-9]{32}\.(jpg|png|gif|webp)$/', $id, $m)) {
    http_response_code(404);
    exit('Not found');
}

$path = realpath($storageDir . DIRECTORY_SEPARATOR . $id);

// Defence in depth: the resolved path must still be inside the storage folder.
if ($path === false || !str_starts_with($path, $storageDir . DIRECTORY_SEPARATOR) || !is_file($path)) {
    http_response_code(404);
    exit('Not found');
}

header('Content-Type: ' . TYPES[$m[1]]);
header('Content-Length: ' . filesize($path));
header('Content-Disposition: inline; filename="' . $id . '"');
header('X-Content-Type-Options: nosniff');
header("Content-Security-Policy: default-src 'none'; sandbox");
header('Cache-Control: private, max-age=3600');

readfile($path);
