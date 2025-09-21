# Lumen Files PHP Client SDK

A lightweight PHP 8.2+ helper for uploading files to a Lumen Files drive. The client wraps the HTTP workflow described in the official documentation and provides both simple and multipart upload helpers.

## Installation

```bash
composer require lumen/php-client-sdk
```

## Usage

```php
<?php

require __DIR__ . '/vendor/autoload.php';

use Lumen\Files\LumenFilesClient;

$client = new LumenFilesClient('https://fsn1-1.files.lumen.cool', defaultHeaders: [
    'Authorization' => 'Bearer YOUR_TOKEN',
]);

// Simple upload (small files)
$response = $client->simpleUpload(__DIR__ . '/photo.jpg', 'DRIVE_ID', [
    'parents' => ['FOLDER_ID'],
]);

// Multipart upload (large files)
$response = $client->multipartUpload(__DIR__ . '/movie.mp4', 'DRIVE_ID', [
    'chunk_size' => 16 * 1024 * 1024,
    'on_progress' => function (int $partNumber, int $offset, int $bytesUploaded, int $totalBytes): void {
        printf("Uploaded part %d (%d/%d bytes)\n", $partNumber, $bytesUploaded, $totalBytes);
    },
]);
```

### Manual multipart control

If you prefer to control the multipart flow yourself you can use the lower-level helpers:

```php
$init = $client->initializeMultipartUpload('DRIVE_ID', 'movie.mp4', 2147483648, 'video/mp4');
$uploadId = $init['id'];

$part1 = file_get_contents('movie.part1');
$client->uploadMultipartPart($uploadId, 1, $part1); // automatically calculates part ETag

$parts = [
    ['part_number' => 1, 'etag' => md5($part1)],
];
$overallEtag = $client->calculateMultipartEtag($parts);

$client->completeMultipartUpload($uploadId, $parts, $overallEtag);
```

### ETag utilities

`calculateMultipartEtag()` implements the MD5 concatenation algorithm required by Lumen (identical to the S3 multipart ETag calculation). You can feed it the `etag` values returned by `uploadMultipartPart()` and pass the resulting string to `completeMultipartUpload()`.

### Error handling

The client uses Guzzle under the hood. HTTP errors (4xx/5xx) will throw `GuzzleHttp\\Exception\\GuzzleException`. File-system errors throw `RuntimeException`.

### Testing

Install dependencies and run PHPUnit:

```bash
composer install
vendor/bin/phpunit
```

No tests are bundled yet; you can add your own in the `tests/` directory.
