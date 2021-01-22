<?php

/**
 * @copyright Copyright (c) 2021 Setasign GmbH & Co. KG (https://www.setasign.com)
 * @license   http://opensource.org/licenses/mit-license The MIT License
 */

namespace setasign\SetaPDF\Signer\Module\AwsKMS;

use Aws\Kms\KmsClient;
use SetaPDF_Core_Reader_FilePath;
use SetaPDF_Core_Type_Dictionary;
use SetaPDF_Core_Document as Document;
use SetaPDF_Signer_Asn1_Element as Asn1Element;
use SetaPDF_Signer_Asn1_Oid as Asn1Oid;
use SetaPDF_Signer_Digest as Digest;
use SetaPDF_Signer_Exception;
use SetaPDF_Signer_Signature_DictionaryInterface;
use SetaPDF_Signer_Signature_DocumentInterface;
use SetaPDF_Signer_Signature_Module_ModuleInterface;
use SetaPDF_Signer_Signature_Module_Pades;

class Module implements
    SetaPDF_Signer_Signature_Module_ModuleInterface,
    SetaPDF_Signer_Signature_DictionaryInterface,
    SetaPDF_Signer_Signature_DocumentInterface
{
    /**
     * @var KmsClient
     */
    protected $kmsClient;

    /**
     * @var SetaPDF_Signer_Signature_Module_Pades Internal pades module.
     */
    protected $padesModule;

    /**
     * @var string
     */
    protected $keyId;

    /**
     * @var string|null
     */
    protected $signatureAlgorithm;

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
        $this->padesModule = new SetaPDF_Signer_Signature_Module_Pades();
    }

    /**
     * @param $certificate
     * @throws \SetaPDF_Signer_Asn1_Exception
     */
    public function setCertificate($certificate)
    {
        $this->padesModule->setCertificate($certificate);
    }

    /**
     * @param string $signatureAlgorithm
     */
    public function setSignatureAlgorithm($signatureAlgorithm)
    {
        switch ($signatureAlgorithm) {
            case 'RSASSA_PKCS1_V1_5_SHA_256':
            case 'RSASSA_PSS_SHA_256':
            case 'ECDSA_SHA_256':
                $this->padesModule->setDigest(Digest::SHA_256);
                break;
            case 'RSASSA_PKCS1_V1_5_SHA_384':
            case 'RSASSA_PSS_SHA_384':
            case 'ECDSA_SHA_384':
                $this->padesModule->setDigest(Digest::SHA_384);
                break;
            case 'RSASSA_PKCS1_V1_5_SHA_512':
            case 'RSASSA_PSS_SHA_512':
            case 'ECDSA_SHA_512':
                $this->padesModule->setDigest(Digest::SHA_512);
                break;
            default:
                throw new Exception('Unknown algorithm "%s".', $signatureAlgorithm);
        }

        $this->signatureAlgorithm = $signatureAlgorithm;
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
    public function updateSignatureDictionary(SetaPDF_Core_Type_Dictionary $dictionary)
    {
        $this->padesModule->updateSignatureDictionary($dictionary);
    }

    /**
     * @inheritDoc
     */
    public function updateDocument(Document $document)
    {
        $this->padesModule->updateDocument($document);
    }

    /**
     * Get the complete Cryptographic Message Syntax structure.
     *
     * @return Asn1Element
     * @throws SetaPDF_Signer_Exception
     */
    public function getCms()
    {
        return $this->padesModule->getCms();
    }

    /**
     * @inheritDoc
     */
    public function createSignature(SetaPDF_Core_Reader_FilePath $tmpPath)
    {
        // ensure certificate
        $certificate = $this->padesModule->getCertificate();
        if ($certificate === null) {
            throw new \BadMethodCallException('Missing certificate!');
        }

        $padesDigest = $this->padesModule->getDigest();
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

            $cms = $this->padesModule->getCms();

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
                                        Asn1Oid::encode(Digest::getOid($padesDigest))
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
                                                Asn1Oid::encode(Digest::getOid($padesDigest))
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
        $hashData = $this->padesModule->getDataToSign($tmpPath);

        $result = $this->kmsClient->sign([
            'KeyId' => $this->keyId, // REQUIRED
            'Message' => hash($padesDigest, $hashData, true),
            'MessageType' => 'DIGEST', // RAW|DIGEST
            'SigningAlgorithm' => $signatureAlgorithm
        ]);
        $signatureValue = $result->get('Signature');

        // pass it to the module
        $this->padesModule->setSignatureValue((string) $signatureValue);
        return (string) $this->padesModule->getCms();
    }
}
