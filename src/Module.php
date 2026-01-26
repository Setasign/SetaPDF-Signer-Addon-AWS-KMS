<?php

/**
 * @copyright Copyright (c) 2026 Setasign GmbH & Co. KG (https://www.setasign.com)
 * @license   http://opensource.org/licenses/mit-license The MIT License
 */

namespace setasign\SetaPDF\Signer\Module\AwsKMS;

use Aws\Kms\KmsClient;
use setasign\SetaPDF2\Core\Reader\FilePath;
use setasign\SetaPDF2\Signer\Asn1\Element as Asn1Element;
use setasign\SetaPDF2\Signer\Asn1\Oid as Asn1Oid;
use setasign\SetaPDF2\Signer\Digest;
use setasign\SetaPDF2\Signer\Signature\Module\DictionaryInterface;
use setasign\SetaPDF2\Signer\Signature\Module\DocumentInterface;
use setasign\SetaPDF2\Signer\Signature\Module\ModuleInterface;
use setasign\SetaPDF2\Signer\Signature\Module\PadesProxyTrait;

class Module implements
    ModuleInterface,
    DictionaryInterface,
    DocumentInterface
{
    use PadesProxyTrait;

    protected KmsClient $kmsClient;
    protected string $keyId;
    protected ?string $signatureAlgorithm;

    /**
     * Module constructor.
     *
     * @param string $keyId
     * @param KmsClient $kmsClient
     */
    public function __construct($keyId, KmsClient $kmsClient)
    {
        $this->keyId = $keyId;
        $this->kmsClient = $kmsClient;
    }

    /**
     * @param string $signatureAlgorithm
     * @throws Exception
     */
    public function setSignatureAlgorithm($signatureAlgorithm)
    {
        $digest = match ($signatureAlgorithm) {
            'RSASSA_PKCS1_V1_5_SHA_256', 'RSASSA_PSS_SHA_256', 'ECDSA_SHA_256' => Digest::SHA_256,
            'RSASSA_PKCS1_V1_5_SHA_384', 'RSASSA_PSS_SHA_384', 'ECDSA_SHA_384' => Digest::SHA_384,
            'RSASSA_PKCS1_V1_5_SHA_512', 'RSASSA_PSS_SHA_512', 'ECDSA_SHA_512' => Digest::SHA_512,
            default => throw new Exception('Unknown algorithm "%s".', $signatureAlgorithm),
        };

        $this->signatureAlgorithm = $signatureAlgorithm;
        $this->_getPadesModule()->setDigest($digest);
    }

    /**
     * @return string|null
     */
    public function getSignatureAlgorithm()
    {
        return $this->signatureAlgorithm;
    }

    /**
     * @inheritDoc
     */
    public function createSignature(FilePath $tmpPath)
    {
        // ensure certificate
        $certificate = $this->getCertificate();
        if ($certificate === null) {
            throw new \BadMethodCallException('Missing certificate!');
        }

        $module = $this->_getPadesModule();
        $digest = $module->getDigest();
        $signatureAlgorithm = $this->signatureAlgorithm;
        if ($signatureAlgorithm === null) {
            throw new \BadMethodCallException('Missing signature algorithm');
        }

        $algorithmsWithPssPadding = [
            'RSASSA_PSS_SHA_256',
            'RSASSA_PSS_SHA_384',
            'RSASSA_PSS_SHA_512',
        ];
        // update CMS SignatureAlgorithmIdentifier according to Probabilistic Signature Scheme (RSASSA-PSS)
        if (\in_array($signatureAlgorithm, $algorithmsWithPssPadding, true)) {
            // the algorihms are linked to https://tools.ietf.org/html/rfc7518#section-3.5 which says:
            // "The size of the salt value is the same size as the hash function output."
            $saltLength = 256 / 8;
            if ($signatureAlgorithm === 'RSASSA_PSS_SHA_384') {
                $saltLength = 384 / 8;
            } elseif ($signatureAlgorithm === 'RSASSA_PSS_SHA_512') {
                $saltLength = 512 / 8;
            }

            $cms = $module->getCms();

            $signatureAlgorithmIdentifier = Asn1Element::findByPath('1/0/4/0/4', $cms);
            $signatureAlgorithmIdentifier->getChild(0)->setValue(
                Asn1Oid::encode("1.2.840.113549.1.1.10")
            );
            $signatureAlgorithmIdentifier->removeChild($signatureAlgorithmIdentifier->getChild(1));
            $signatureAlgorithmIdentifier->addChild(new Asn1Element(
                Asn1Element::SEQUENCE | Asn1Element::IS_CONSTRUCTED,
                '',
                [
                    new Asn1Element(
                        Asn1Element::TAG_CLASS_CONTEXT_SPECIFIC | Asn1Element::IS_CONSTRUCTED,
                        '',
                        [
                            new Asn1Element(
                                Asn1Element::SEQUENCE | Asn1Element::IS_CONSTRUCTED,
                                '',
                                [
                                    new Asn1Element(
                                        Asn1Element::OBJECT_IDENTIFIER,
                                        Asn1Oid::encode(Digest::getOid($digest))
                                    ),
                                    new Asn1Element(Asn1Element::NULL)
                                ]
                            )
                        ]
                    ),
                    new Asn1Element(
                        Asn1Element::TAG_CLASS_CONTEXT_SPECIFIC | Asn1Element::IS_CONSTRUCTED | "\x01",
                        '',
                        [
                            new Asn1Element(
                                Asn1Element::SEQUENCE | Asn1Element::IS_CONSTRUCTED,
                                '',
                                [
                                    new Asn1Element(
                                        Asn1Element::OBJECT_IDENTIFIER,
                                        Asn1Oid::encode('1.2.840.113549.1.1.8')
                                    ),
                                    new Asn1Element(
                                        Asn1Element::SEQUENCE | Asn1Element::IS_CONSTRUCTED,
                                        '',
                                        [
                                            new Asn1Element(
                                                Asn1Element::OBJECT_IDENTIFIER,
                                                Asn1Oid::encode(Digest::getOid($digest))
                                            ),
                                            new Asn1Element(Asn1Element::NULL)
                                        ]
                                    )
                                ]
                            )
                        ]
                    ),
                    new Asn1Element(
                        Asn1Element::TAG_CLASS_CONTEXT_SPECIFIC | Asn1Element::IS_CONSTRUCTED | "\x02",
                        '',
                        [
                            new Asn1Element(Asn1Element::INTEGER, \chr($saltLength))
                        ]
                    )
                ]
            ));
        }

        // get the hash data from the module
        $hashData = $module->getDataToSign($tmpPath);

        $result = $this->kmsClient->sign([
            'KeyId' => $this->keyId, // REQUIRED
            'Message' => hash($digest, $hashData, true),
            'MessageType' => 'DIGEST', // RAW|DIGEST
            'SigningAlgorithm' => $signatureAlgorithm
        ]);
        $signatureValue = $result->get('Signature');

        // pass it to the module
        $module->setSignatureValue((string) $signatureValue);
        return (string) $module->getCms();
    }
}
