<?php

use Aws\Kms\KmsClient;
use setasign\SetaPDF\Signer\Module\AwsKMS\Module;

require_once __DIR__ . '/../vendor/autoload.php';

$fileToSign = __DIR__ . '/assets/Laboratory-Report.pdf';
$resultPath = 'signed.pdf';

$settings = require 'settings.php';
$region = $settings['region'];
$version = $settings['version'];
$keyId = $settings['keyId'];
$cert = $settings['cert'];
$digest = $settings['digest'];
$signatureAlgorithm = $settings['algorithm'];

$kmsClient = new KmsClient([
    'region' => $region,
    'version' => $version,
]);
$awsKmsModule = new Module($kmsClient, $keyId);

$awsKmsModule->setCertificate($cert);
$awsKmsModule->setDigest($digest);
$awsKmsModule->setSignatureAlgorithm($signatureAlgorithm);

// create a writer instance
$writer = new SetaPDF_Core_Writer_File($resultPath);
// create the document instance
$document = SetaPDF_Core_Document::loadByFilename($fileToSign, $writer);

// create the signer instance
$signer = new SetaPDF_Signer($document);
$signer->sign($awsKmsModule);
