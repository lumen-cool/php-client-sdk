<?php

use Lumen\Sdk\LumenKeyManager;

require_once 'vendor/autoload.php';

$encFilename = __DIR__ . '/video.mp4.enc';
$outFilename = __DIR__ . '/video.mp4';
$mnemonic = 'crime once live page tomorrow always column away cancel science shiver project oyster promote barely casino wagon fish pencil shaft bean maze ring rabbit';
$fileSalt = base64_decode('Z/M4NLciagKqNV67xNqQpA=="');
$chunkSize = 16777216; // 16 MiB

$masterKey = LumenKeyManager::deriveMasterKeyFromMnemonic($mnemonic);
$fileKey = LumenKeyManager::deriveFileKey($masterKey, $fileSalt);

$inHandle = fopen($encFilename, 'rb');
if ($inHandle === false) {
    throw new RuntimeException('Failed to open input file.');
}

$outHandle = fopen($outFilename, 'wb');
if ($outHandle === false) {
    throw new RuntimeException('Failed to open output file.');
}

$partNumber = 0;
while (!feof($inHandle)) {
    $blob = fread($inHandle, $chunkSize + 16); // ciphertext + tag
    if ($blob === false || $blob === '') {
        break;
    }
    $iv = LumenKeyManager::deriveChunkIv($fileSalt, $partNumber);
    $pt = LumenKeyManager::decryptPart($blob, $fileKey, $iv, LumenKeyManager::AAD_FILE);
    fwrite($outHandle, $pt);
    printf("Decrypted part %d (%d bytes)\n", $partNumber + 1, strlen($pt));
    $partNumber++;
}

fclose($inHandle);
fclose($outHandle);
printf("Decrypted file written to %s\n", $outFilename);