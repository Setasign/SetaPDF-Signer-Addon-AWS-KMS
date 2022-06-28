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
$signatureAlgorithm = $settings['algorithm'];

$kmsClient = new KmsClient([
    'region' => $region,
    'version' => $version,
]);
$awsKmsModule = new Module($keyId, $kmsClient);

$awsKmsModule->setCertificate($cert);
$awsKmsModule->setSignatureAlgorithm($signatureAlgorithm);

// create a writer instance
$writer = new SetaPDF_Core_Writer_File($resultPath);
// create the document instance
$document = SetaPDF_Core_Document::loadByFilename($fileToSign, $writer);

// create the signer instance
$signer = new SetaPDF_Signer($document);

$field = $signer->addSignatureField(
    'Signature',
    1,
    SetaPDF_Signer_SignatureField::POSITION_RIGHT_TOP,
    ['x' => -160, 'y' => -100],
    180,
    60
);

$signer->setSignatureFieldName($field->getQualifiedName());

$appearance = new SetaPDF_Signer_Signature_Appearance_Dynamic($awsKmsModule);
$signer->setAppearance($appearance);

$signer->sign($awsKmsModule);
