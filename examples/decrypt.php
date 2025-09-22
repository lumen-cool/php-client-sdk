<?php

use Lumen\Sdk\LumenKeyManager;

require_once 'vendor/autoload.php';

$encFilename = __DIR__ . '/image.jpg.enc';
$outFilename = __DIR__ . '/image.jpg';
$mnemonic = 'crime once live page tomorrow always column away cancel science shiver project oyster promote barely casino wagon fish pencil shaft bean maze ring rabbit';
$fileSalt = base64_decode('m5DP7AP4D38iPqTcOUTJKw==');

$masterKey = LumenKeyManager::deriveMasterKeyFromMnemonic($mnemonic);
$fileKey = LumenKeyManager::deriveFileKey($masterKey, $fileSalt);

$blob = file_get_contents($encFilename);
$iv = LumenKeyManager::deriveChunkIv($fileSalt, 0);
$plaintext = LumenKeyManager::decryptPart($blob, $fileKey, $iv, LumenKeyManager::AAD_FILE);
$written = file_put_contents($outFilename, $plaintext, LOCK_EX);

echo sprintf("Decrypted file written to %s (bytes: %d)\n", $outFilename, $written);
