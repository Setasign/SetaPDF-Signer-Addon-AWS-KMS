#  SetaPDF-Signer component module for the AWS KMS.

This package offers a module for the [SetaPDF-Signer](https://www.setasign.com/signer) component that allow you to use
the [AWS Key Management Service](https://aws.amazon.com/kms/) to **digital sign PDF documents in pure PHP**.

## Requirements

This package uses the official
[AWS SDK for PHP Version 3](https://docs.aws.amazon.com/sdk-for-php/v3/developer-guide/welcome.html)
to communicate with the KMS. You need appropriate credentials.

You also need a X.509 certificates related to your stored keys. To create a self-signed certificate for testing purpose
or to create a CSR for the certificate authority of your choice, you can use a tool we prepared
[here](https://github.com/Setasign/Cloud-KMS-CSR).

The current version of the package is developed and tested on PHP >= 8.1 up to PHP 8.5. Requirements of the 
[SetaPDF-Signer](https://www.setasign.com/signer) component can be found 
[here](https://manuals.setasign.com/setapdf-signer-manual/getting-started/#index-1).

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
are assigned or use an access token which you can create in your personal 
[composer settings](https://www.setasign.com/my-setasign/composer-settings/#bearer-authentication) 
on setasign.com.
See [here](https://getcomposer.org/doc/articles/authentication-for-private-packages.md#http-basic)
for more options for authentication with composer.

**You have to define your credentials for AWS KMS as documented 
[here](https://docs.aws.amazon.com/sdk-for-php/v3/developer-guide/guide_credentials_default_chain.html).**

## Usage

All classes in this package are located in the namespace `setasign\SetaPDF\Signer\Module\AwsKms`.

### The `Module` class

This is the main signature module which can be used with the [SetaPDF-Signer](https://www.setasign.com/signer)
component. 

A simple complete signature process would look like this:

```php
use Aws\Kms\KmsClient;
use setasign\SetaPDF\Signer\Module\AwsKMS\Module;
use setasign\SetaPDF2\Core\Document;
use setasign\SetaPDF2\Core\Writer\FileWriter;
use setasign\SetaPDF2\Signer\Signer;

$kmsClient = new KmsClient([
    'region' => $region,
    'version' => $version,
]);
$awsKmsModule = new Module($keyId, $kmsClient);

$cert = file_get_contents('your-cert.crt');
$awsKmsModule->setCertificate($cert);
$awsKmsModule->setSignatureAlgorithm($algorithm);

// the file to sign
$fileToSign = __DIR__ . '/Laboratory-Report.pdf';

// create a writer instance
$writer = new FileWriter('signed.pdf');
// create the document instance
$document = Document::loadByFilename($fileToSign, $writer);

// create the signer instance
$signer = new Signer($document);
$signer->sign($awsKmsModule);
```

Make sure that you pass `$algorithm` value which match the configuration of the key in the KMS.

## License

This package is open-sourced software licensed under the [MIT license](https://opensource.org/licenses/MIT).
