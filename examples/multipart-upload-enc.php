<?php

require_once 'vendor/autoload.php';

use Lumen\Sdk\LumenClient;
use Lumen\Sdk\LumenVaultResolver;
use Nyra\Bip39\Bip39;

$mnemonic = 'crime once live page tomorrow always column away cancel science shiver project oyster promote barely casino wagon fish pencil shaft bean maze ring rabbit';

if (!Bip39::isValidMnemonic($mnemonic)) {
    throw new RuntimeException('Invalid BIP-39 mnemonic.');
}

$resolver = new LumenVaultResolver();
$resolver->loadFromRegistry('https://api.lumen.cool/v1/vaults');

$client = new LumenClient(
    vaultResolver: $resolver,
    defaultHeaders: [
        'Authorization' => 'Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJhdWQiOiI5ZGViMDU4MC0xY2FhLTQ0ODMtOWRlMi1lNDA3OTlhNjg2MTkiLCJqdGkiOiJjNmMwNzgwZjZhNTk5YjBjNWNlZWNkYzAwYmZhYTZhM2IwMmYyMTFiMzI2ZTc2NGEwY2RiMzBiYzhkNmEwMGE5N2U3NmQyYThlOWNhNDIyYSIsImlhdCI6MTc1ODU3MDcxMS41ODI0MDQsIm5iZiI6MTc1ODU3MDcxMS41ODI0MDUsImV4cCI6MTc5MDEwNjcxMS41NzgzOTUsInN1YiI6IjEiLCJzY29wZXMiOlsib3BlbmlkIiwicHJvZmlsZSIsImVtYWlsIiwiZHJpdmUiLCJkcml2ZS5hY3Rpdml0eSJdfQ.JIn80CxK7E-I_GEHTcRh_VlF_1Kj8RK8kpXfyUIcI0-WqHUoJgk90b2gWJaTuqJ5hl2dMkS4pX5-dBdi9aVAQcN475dtkike74S48g4obCPPWH0utllsUMYjrxnCoSTJi48Jii-OMdGdlbYpIgUtwm4I0cScY7fm9CnSu-8sbagZBgwQV44J7J4l1Tpy8BPSKhOeSzzYIdDfQaB75aC3ft9LVrj-vDkFrwzh_SKQKnAfqVEhe1rt_izn9WyUdhMMoGm6_MAdkEAU9oKBkFPRqo2XoQkHWJ7V1ziRg0EZ30CM5_-Gl0OqklU0mm7RmAnJTSVR1elQMEIjTGK4L8J3WJWTRdot151y1_DkdgiMY0SotbKNrN7-QU4nc4l8b-UgjNZTHoJDKE8QVLyvHPWybypTwobB2gI0v0mnq5WvI-2Hsp9cmpgR40vi6L0Az5Wi2J7rKlsZQC-9eTpf8S8Cl0eApxZE6DuWKWqJ6Cmm3mECMOv5EhP-Hfrhq1H7jaVtE1Dx1NKA2qnhm3CrXikv0wvCVzEzVljX4a8Kae9xqNuYodXKbflXlOQ8XXTrgojkbiruhIxFzLzmIIJAV9HL4PwpgTnSTn-0u3X_VGx44JzdcaQhSTNNzp-1JLDRIu4tjsMsJ7m1yD_XRT-fQGoDMWFaQuJtCHE6jOyJ7a8hR7M',
    ],
);

$file = $client->multipartUpload(
    filePath: __DIR__ . '/large-video.mp4',
    driveId: '01jns7j69jfgj3fd5ntsp3sm07-kw2',
    options: [
        'parents' => ['01jns7j69jfgj3fd5ntsp3sm07'],
        'encryption' => ['mnemonic' => $mnemonic, 'passphrase' => ''],
        'mime_type' => 'image/jpeg',
        'chunk_size' => 16 * 1024 * 1024,
        'on_progress' => static function (int $partNumber, int $offset, int $bytesUploaded, int $totalBytes): void {
            printf("Uploaded part %d (%d/%d bytes)\n", $partNumber, $bytesUploaded, $totalBytes);
        },
    ]
);

printf(
    "Uploaded %s (%d bytes) to vault %s\n",
    $file->getFile()->getId(),
    $file->getFile()->getSize(),
    $file->getFile()->getVaultSlug(),
);

