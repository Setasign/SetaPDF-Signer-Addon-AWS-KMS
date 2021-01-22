#  SetaPDF-Signer component module for the AWS KMS.

This package offers a module for the [SetaPDF-Signer](https://www.setasign.com/signer) component that allow you to use
the [AWS Key Management Service](https://aws.amazon.com/kms/) to **digital sign PDF documents in pure PHP**.

## Requirements

This package uses the official
[AWS SDK for PHP Version 3](https://docs.aws.amazon.com/sdk-for-php/v3/developer-guide/welcome.html)
to communicate with the KMS service. You need appropriate credentials.

You also need a X.509 certificates related to your stored keys. To create a self-signed certificate for testing purpose
or to create a CSR for the certificate authority of your choice, you can use a tool we prepared
[here](https://github.com/Setasign/Cloud-KMS-CSR).

The package is developed and tested on PHP >= 5.6. Requirements of the [SetaPDF-Signer](https://www.setasign.com/signer)
component can be found [here](https://manuals.setasign.com/setapdf-signer-manual/getting-started/#index-1).

## Installation
Add following to your composer.json:

```json
{
    "require": {
        "setasign/setapdf-signer-addon-aws-kms": "^1.0"
    },
    "repositories": [
        {
            "type": "composer",
            "url": "https://www.setasign.com/downloads/"
        }
    ]
}
```

and execute `composer update`. You need to define the `repository` to evaluate the dependency to the
[SetaPDF-Signer](https://www.setasign.com/signer) component
(see [here](https://getcomposer.org/doc/faqs/why-can%27t-composer-load-repositories-recursively.md) for more details).

The Setasign repository requires authentication data: You can use your credentials
of your account at [setasign.com](https://www.setasign.com) to which your licenses
are assigned. You will be asked for this during a composer run. See
[here](https://getcomposer.org/doc/articles/authentication-for-private-packages.md#http-basic)
for more options for authentication with composer.

**You have to define your credentials for AWS KMS in [environment variables](https://docs.aws.amazon.com/sdk-for-php/v3/developer-guide/guide_credentials_environment.html).**


### Evaluation version
By default this packages depends on a licensed version of the [SetaPDF-Signer](https://www.setasign.com/signer)
component. If you want to use it with an [evaluation version](https://www.setasign.com/products/setapdf-signer/evaluate/)
please use following in your composer.json:

```json
{
    "require": {
        "setasign/setapdf-signer-addon-aws-kms": "dev-evaluation"
    },
    "repositories": [
        {
            "type": "composer",
            "url": "https://www.setasign.com/downloads/"
        }
    ]
}
```

## Usage

All classes in this package are located in the namespace `setasign\SetaPDF\Signer\Module\AwsKms`.

### The `Module` class

This is the main signature module which can be used with the [SetaPDF-Signer](https://www.setasign.com/signer)
component. 

A simple complete signature process would look like this:

```php
$kmsClient = new Aws\Kms\KmsClient\KmsClient([
    'region' => $region,
    'version' => $version,
]);
$awsKmsModule = new setasign\SetaPDF\Signer\Module\AwsKms\Module($keyId, $kmsClient);

$cert = file_get_contents('your-cert.crt');
$awsKmsModule->setCertificate($cert);
$awsKmsModule->setDigest($digest);
$awsKmsModule->setSignatureAlgorithm($algorithm);

// the file to sign
$fileToSign = __DIR__ . '/Laboratory-Report.pdf';

// create a writer instance
$writer = new SetaPDF_Core_Writer_File('signed.pdf');
// create the document instance
$document = SetaPDF_Core_Document::loadByFilename($fileToSign, $writer);

// create the signer instance
$signer = new SetaPDF_Signer($document);
$signer->sign($awsKmsModule);
```

Make sure that you pass `$digest` and `$algorithm` values which match the configuration of the key in the KMS.

## License

This package is open-sourced software licensed under the [MIT license](https://opensource.org/licenses/MIT).
