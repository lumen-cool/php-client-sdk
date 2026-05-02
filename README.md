# Lumen PHP Client SDK

A lightweight PHP 8.2+ SDK for interacting with Lumen Files uploads. It provides:

* A `LumenVaultResolver` that can hydrate vault definitions from the public registry and from custom overrides.
* A `LumenClient` that automatically targets the right vault, either from a default selection or from the drive ID annotation (`{drive}-{vault}`).
* Strongly-typed response objects for both simple and multipart uploads.

## Installation

```bash
composer require lumen-cool/sdk
```

## Getting started

```php
<?php

require __DIR__ . '/vendor/autoload.php';

use Lumen\Sdk\LumenClient;
use Lumen\Sdk\LumenVaultResolver;

$resolver = new LumenVaultResolver();
$resolver->loadFromRegistry('https://lumen.cool/api/vaults');
$resolver->addCustomVault('local', 'http://localhost:8000', name: 'Local development');

$client = new LumenClient(
    vaultResolver: $resolver,
    defaultHeaders: [
        'Authorization' => 'Bearer YOUR_TOKEN',
    ],
);

// Optional: set a default vault once
$client->setVault('kw2');
```

### Simple upload

```php
use Lumen\Sdk\Response\FileResource;

/** @var FileResource $file */
$file = $client->simpleUpload(__DIR__ . '/photo.jpg', '01jh2tcnx48caj4wsdkjevtr2h');

printf(
    "Uploaded %s (%d bytes) to vault %s\n",
    $file->getName(),
    $file->getSize(),
    $file->getVaultSlug(),
);
```

If you prefer to embed the vault in the drive identifier, pass `"{drive}-{vault}"` as the `drive_id`. The client will split it automatically:

```php
$file = $client->simpleUpload(__DIR__ . '/photo.jpg', '01jh2tcnx48caj4wsdkjevtr2h-kw2');
```

### Encrypted upload

```php
$mnemonic = 'your bip39 mnemonic phrase ...';

$file = $client->upload(__DIR__ . '/photo.jpg', '01jh2tcnx48caj4wsdkjevtr2h', [
    'mime_type' => 'image/jpeg',
    'encryption' => [
        'mnemonic' => $mnemonic
    ]
]);

// Optionally interact with the keys (if you want to share the file)
use Lumen\Sdk\LumenKeyManager;

$masterKey = LumenKeyManager::deriveMasterKeyFromMnemonic($mnemonic);
$fileKey = LumenKeyManager::unwrapFileKey(
    base64_decode(
        string: $file->toArray()['encryption']['wrapped_key'],
        strict: true
    ),
    $masterKey
);

$shareableLink = $client->generateShareableLink('https://app.lumen.cool', $file->getFederatedId(), $fileKey);
```

### Download file

Files can be downloaded directly from a vault. If the file is encrypted, you can pass the `raw_file_key` obtained from a shareable link or unwrapped using your mnemonic.

```php
// Unencrypted file download
$client->downloadFile('01jh2tcnx48caj4wsdkjevtr2h', 'downloaded.jpg');

// Encrypted file download (requires the unwrapped file key)
$client->downloadFile('01kqjxmvfpjshe0vbs9jbzsa5q-kw2', 'decrypted.jpg', [
    'raw_file_key' => $fileKey, // Binary string or Base64URL encoded
    // or using 'encryption' => ['mnemonic' => $mnemonic] to derive the key on-the-fly
]);
```

### Multipart upload (automatic)

```php
use Lumen\Sdk\Response\MultipartUploadResult;

/** @var MultipartUploadResult $result */
$result = $client->multipartUpload(__DIR__ . '/movie.mp4', '01jh2tcnx48caj4wsdkjevtr2h', [
    'chunk_size' => 16 * 1024 * 1024,
    'on_progress' => static function (int $partNumber, int $offset, int $bytesUploaded, int $totalBytes): void {
        printf("Uploaded part %d (%d/%d bytes)\n", $partNumber, $bytesUploaded, $totalBytes);
    },
]);

$uploaded = $result->getFile();
```

### Multipart upload (manual control)

```php
use Lumen\Sdk\Response\MultipartUploadPart;
use Lumen\Sdk\Response\MultipartUploadSession;

$session = $client->initializeMultipartUpload(
    '01jh2tcnx48caj4wsdkjevtr2h',
    'movie.mp4',
    2_147_483_648,
    ['mime_type' => 'video/mp4'],
);

$part = file_get_contents(__DIR__ . '/movie.part1');
$partResponse = $client->uploadMultipartPart($session, 1, $part);

$parts = [
    ['part_number' => $partResponse->getPartNumber(), 'etag' => $partResponse->getEtag()],
];

$overallEtag = $client->calculateMultipartEtag($parts);

$result = $client->completeMultipartUpload($session, $parts, $overallEtag);
```

### Vault resolution helpers

The resolver can also map arbitrary URLs back to a vault, which is useful when handling callbacks:

```php
$vault = $resolver->resolveFromUrl('https://fsn1-1.files.lumen.cool/v1/files');
```

## Error handling

* HTTP failures bubble up as `GuzzleHttp\Exception\GuzzleException`.
* File-system issues throw `RuntimeException`.
* JSON decoding uses `JSON_THROW_ON_ERROR` to surface malformed responses.

## Testing

```bash
composer install
composer validate
```

No tests are bundled yet; you can add your own in the `tests/` directory.

## 📄 License

This project is licensed under the **GNU Affero General Public License v3 (AGPLv3)**. See the [LICENSE](./LICENSE) file
for details.

Contributions are licensed to the maintainers under both AGPLv3 and the [Apache License 2.0](./LICENSE-maintainers) for
use in commercial or relicensed versions. See [CONTRIBUTING.md](./CONTRIBUTING.md) for details.

## 🤝 Contributing

We welcome community contributions! Please read our [contributing guidelines](./CONTRIBUTING.md) before submitting a
pull request.
