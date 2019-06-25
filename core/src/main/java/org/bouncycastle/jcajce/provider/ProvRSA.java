package org.bouncycastle.jcajce.provider;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.KeySpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.SecretKeyFactorySpi;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cms.GenericHybridParameters;
import org.bouncycastle.asn1.cms.RsaKemParameters;
import org.bouncycastle.asn1.iso.ISOIECObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.ntt.NTTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.RSAESOAEPparams;
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.AsymmetricKeyPairGenerator;
import org.bouncycastle.crypto.AsymmetricOperatorFactory;
import org.bouncycastle.crypto.AsymmetricPrivateKey;
import org.bouncycastle.crypto.AsymmetricPublicKey;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.DigestAlgorithm;
import org.bouncycastle.crypto.EncapsulatedSecretExtractor;
import org.bouncycastle.crypto.EncapsulatingSecretGenerator;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.KDFCalculator;
import org.bouncycastle.crypto.KeyWrapOperatorFactory;
import org.bouncycastle.crypto.OutputSigner;
import org.bouncycastle.crypto.OutputVerifier;
import org.bouncycastle.crypto.Parameters;
import org.bouncycastle.crypto.PlainInputProcessingException;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.SignatureOperatorFactory;
import org.bouncycastle.crypto.SignatureWithMessageRecoveryOperatorFactory;
import org.bouncycastle.crypto.asymmetric.AsymmetricKeyPair;
import org.bouncycastle.crypto.asymmetric.AsymmetricRSAPrivateKey;
import org.bouncycastle.crypto.asymmetric.AsymmetricRSAPublicKey;
import org.bouncycastle.crypto.fips.FipsAlgorithm;
import org.bouncycastle.crypto.fips.FipsDigestAlgorithm;
import org.bouncycastle.crypto.fips.FipsKDF;
import org.bouncycastle.crypto.fips.FipsParameters;
import org.bouncycastle.crypto.fips.FipsRSA;
import org.bouncycastle.crypto.fips.FipsSHS;
import org.bouncycastle.crypto.fips.FipsUnapprovedOperationError;
import org.bouncycastle.crypto.general.GeneralAlgorithm;
import org.bouncycastle.crypto.general.RSA;
import org.bouncycastle.crypto.general.SecureHash;
import org.bouncycastle.jcajce.AgreedKeyWithMacKey;
import org.bouncycastle.jcajce.KTSKeyWithEncapsulation;
import org.bouncycastle.jcajce.ZeroizableSecretKey;
import org.bouncycastle.jcajce.spec.KTSExtractKeySpec;
import org.bouncycastle.jcajce.spec.KTSGenerateKeySpec;
import org.bouncycastle.jcajce.spec.KTSKeySpec;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.bouncycastle.jcajce.spec.KTSWithKEMKWSKeySpec;
import org.bouncycastle.jcajce.util.MessageDigestUtils;
import org.bouncycastle.util.Arrays;

class ProvRSA
    extends AsymmetricAlgorithmProvider
{
    private static final KeyIvSizeProvider keySizeProvider = new KeyIvSizeProvider();
    private final SignatureOperatorFactory fipsRsaSigFactory = new FipsRSA.SignatureOperatorFactory();

    private SignatureOperatorFactory generalRsaSigFactory = getGeneralSigFactory();
    private SignatureWithMessageRecoveryOperatorFactory recoveryRsaSigFactory = getRecoverySigFactory();
    private AsymmetricOperatorFactory singleBlockFactory;
    private KeyWrapOperatorFactory generalKeyWrapFactory;

    private static final String PREFIX = "org.bouncycastle.jcajce.provider.asymmetric" + ".rsa.";

    private final FipsAlgorithm[] fipsAlgorithms = new FipsAlgorithm[]{FipsRSA.WRAP_PKCS1v1_5.getAlgorithm(), FipsRSA.WRAP_OAEP.getAlgorithm()};
    private final GeneralAlgorithm[] generalAlgorithms = new GeneralAlgorithm[]{RSA.ALGORITHM, RSA.WRAP_PKCS1v1_5.getAlgorithm(), RSA.WRAP_OAEP.getAlgorithm()};

    private static final PublicKeyConverter<AsymmetricRSAPublicKey> publicKeyConverter = new PublicKeyConverter<AsymmetricRSAPublicKey>()
    {
        public AsymmetricRSAPublicKey convertKey(Algorithm algorithm, PublicKey key)
            throws InvalidKeyException
        {
            if (key instanceof RSAPublicKey)
            {
                if (key instanceof ProvRSAPublicKey)
                {
                    return ((ProvRSAPublicKey)key).getBaseKey();
                }

                return new ProvRSAPublicKey(algorithm, (RSAPublicKey)key).getBaseKey();
            }
            else
            {
                // see if we can build a key from key.getEncoded()
                try
                {
                    return new AsymmetricRSAPublicKey(algorithm, SubjectPublicKeyInfo.getInstance(Utils.getKeyEncoding(key)));
                }
                catch (Exception e)
                {
                    throw new InvalidKeyException("Cannot identify RSA public key: " + e.getMessage(), e);
                }
            }
        }
    };

    private static final PrivateKeyConverter<AsymmetricRSAPrivateKey> privateKeyConverter = new PrivateKeyConverter<AsymmetricRSAPrivateKey>()
    {
        public AsymmetricRSAPrivateKey convertKey(Algorithm algorithm, PrivateKey key)
            throws InvalidKeyException
        {
            if (key instanceof RSAPrivateCrtKey)
            {
                if (key instanceof ProvRSAPrivateCrtKey)
                {
                    return ((ProvRSAPrivateCrtKey)key).getBaseKey();
                }

                return new ProvRSAPrivateCrtKey(algorithm, (RSAPrivateCrtKey)key).getBaseKey();
            }
            else if (key instanceof RSAPrivateKey)
            {
                if (key instanceof ProvRSAPrivateKey)
                {
                    return ((ProvRSAPrivateKey)key).getBaseKey();
                }

                return new ProvRSAPrivateKey(algorithm, (RSAPrivateKey)key).getBaseKey();
            }
            else
            {
                // see if we can build a key from key.getEncoded()
                try
                {
                    return new AsymmetricRSAPrivateKey(algorithm, PrivateKeyInfo.getInstance(Utils.getKeyEncoding(key)));
                }
                catch (Exception e)
                {
                    throw new InvalidKeyException("Cannot identify RSA private key: " + e.getMessage(), e);
                }
            }
        }
    };

    private static final Map<ASN1ObjectIdentifier, FipsKDF.AgreementKDFPRF> kdfPRF = new HashMap<ASN1ObjectIdentifier, FipsKDF.AgreementKDFPRF>();
    private static final Map<ASN1ObjectIdentifier, String> wrapNames = new HashMap<ASN1ObjectIdentifier, String>();
    private static final Map<String, String> generalRsaAttributes = new HashMap<String, String>();

    static
    {
        kdfPRF.put(OIWObjectIdentifiers.idSHA1, FipsKDF.AgreementKDFPRF.SHA1);
        kdfPRF.put(NISTObjectIdentifiers.id_sha224, FipsKDF.AgreementKDFPRF.SHA224);
        kdfPRF.put(NISTObjectIdentifiers.id_sha256, FipsKDF.AgreementKDFPRF.SHA256);
        kdfPRF.put(NISTObjectIdentifiers.id_sha384, FipsKDF.AgreementKDFPRF.SHA384);
        kdfPRF.put(NISTObjectIdentifiers.id_sha512, FipsKDF.AgreementKDFPRF.SHA512);

        wrapNames.put(NISTObjectIdentifiers.id_aes128_wrap, "AES");
        wrapNames.put(NISTObjectIdentifiers.id_aes192_wrap, "AES");
        wrapNames.put(NISTObjectIdentifiers.id_aes256_wrap, "AES");
        wrapNames.put(NTTObjectIdentifiers.id_camellia128_wrap, "Camellia");
        wrapNames.put(NTTObjectIdentifiers.id_camellia192_wrap, "Camellia");
        wrapNames.put(NTTObjectIdentifiers.id_camellia256_wrap, "Camellia");

        generalRsaAttributes.put("SupportedKeyClasses", "java.security.interfaces.RSAPublicKey|java.security.interfaces.RSAPrivateKey");
        generalRsaAttributes.put("SupportedKeyFormats", "PKCS#8|X.509");
    }

    private AsymmetricOperatorFactory getGeneralEncryptionFactory()
    {
        if (CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            return null;
        }

        if (singleBlockFactory == null)
        {
            singleBlockFactory = new RSA.OperatorFactory();
        }

        return singleBlockFactory;
    }

    private KeyWrapOperatorFactory getGeneralWrappingFactory()
    {
        if (CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            return null;
        }

        if (generalKeyWrapFactory == null)
        {
            generalKeyWrapFactory = new RSA.KeyWrapOperatorFactory();
        }

        return generalKeyWrapFactory;
    }

    private SignatureOperatorFactory getGeneralSigFactory()
    {
        if (CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            return null;
        }

        if (generalRsaSigFactory == null)
        {
            generalRsaSigFactory = new RSA.SignatureOperatorFactory();
        }

        return generalRsaSigFactory;
    }

    private SignatureWithMessageRecoveryOperatorFactory getRecoverySigFactory()
    {
        if (CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            return null;
        }

        if (recoveryRsaSigFactory == null)
        {
            recoveryRsaSigFactory = new RSA.SignatureWithMessageRecoveryOperatorFactory();
        }

        return recoveryRsaSigFactory;
    }

    public void configure(final BouncyCastleFipsProvider provider)
    {
        provider.addAlgorithmImplementation("AlgorithmParameters.OAEP", PREFIX + "AlgorithmParametersSpi$OAEP", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new OAEPAlgorithmParameters();
            }
        });
        provider.addAlias("AlgorithmParameters", "OAEP", PKCSObjectIdentifiers.id_RSAES_OAEP);

        provider.addAlgorithmImplementation("AlgorithmParameters.PSS", PREFIX + "AlgorithmParametersSpi$PSS", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new PSSAlgorithmParameters();
            }
        });
        provider.addAlias("AlgorithmParameters", "PSS", "RSAPSS", "RSA-PSS");
        provider.addAlias("AlgorithmParameters", "PSS", PKCSObjectIdentifiers.id_RSASSA_PSS);

        EngineCreator rsaCreator = new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                // use of ternary operation here breaks Android.
                if (CryptoServicesRegistrar.isInApprovedOnlyMode())
                {
                    return build(fipsAlgorithms);
                }

                return build(generalAlgorithms);
            }

            private BaseSingleBlockCipher build(Algorithm[] algorithms)
            {

                return new BaseSingleBlockCipher.Builder(provider, algorithms)
                    .setWrapModeOnly(CryptoServicesRegistrar.isInApprovedOnlyMode())
                    .withFipsOperators(null, new FipsRSA.KeyWrapOperatorFactory())
                    .withGeneralOperators(getGeneralEncryptionFactory(), getGeneralWrappingFactory())
                    .withPublicKeyConverter(publicKeyConverter)
                    .withPrivateKeyConverter(privateKeyConverter)
                    .withParametersCreatorProvider(new ParametersCreatorProvider()
                    {
                        public ParametersCreator get(final Parameters parameters)
                        {
                            return new ParametersCreator()
                            {

                                public Parameters createParameters(boolean forEncryption, AlgorithmParameterSpec spec, SecureRandom random)
                                {
                                    if (CryptoServicesRegistrar.isInApprovedOnlyMode())
                                    {
                                        if (parameters.getAlgorithm() == FipsRSA.WRAP_OAEP.getAlgorithm())
                                        {
                                            return createFipsOaepParameters((OAEPParameterSpec)spec);
                                        }

                                        return FipsRSA.WRAP_PKCS1v1_5;
                                    }
                                    else
                                    {
                                        if (parameters.getAlgorithm() == RSA.WRAP_OAEP.getAlgorithm())
                                        {
                                            OAEPParameterSpec oaepSpec = (OAEPParameterSpec)spec;
                                            DigestAlgorithm digest = Utils.digestNameToAlgMap.get(oaepSpec.getDigestAlgorithm());

                                            MGF1ParameterSpec mgfParams = (MGF1ParameterSpec)oaepSpec.getMGFParameters();
                                            DigestAlgorithm mgfDigest = Utils.digestNameToAlgMap.get(mgfParams.getDigestAlgorithm());

                                            return RSA.WRAP_OAEP.withDigest(digest).withMGFDigest(mgfDigest).withEncodingParams(((PSource.PSpecified)oaepSpec.getPSource()).getValue());
                                        }
                                        else if (parameters.getAlgorithm() == RSA.WRAP_PKCS1v1_5.getAlgorithm())
                                        {
                                            return RSA.WRAP_PKCS1v1_5;
                                        }

                                        return RSA.RAW;
                                    }
                                }
                            };
                        }
                    }).build();
            }
        };

        GuardedEngineCreator pkcs1v15Creator = new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseSingleBlockCipher.Builder(provider, RSA.WRAP_PKCS1v1_5)
                    .withGeneralOperators(getGeneralEncryptionFactory(), getGeneralWrappingFactory())
                    .withPublicKeyConverter(publicKeyConverter)
                    .withPrivateKeyConverter(privateKeyConverter)
                    .withParametersCreatorProvider(new ParametersCreatorProvider()
                    {
                        public ParametersCreator get(final Parameters algorithm)
                        {
                            return new ParametersCreator()
                            {

                                public Parameters createParameters(boolean forEncryption, AlgorithmParameterSpec spec, SecureRandom random)
                                {
                                    return RSA.WRAP_PKCS1v1_5;
                                }
                            };
                        }
                    }).build();
            }
        });

        GuardedEngineCreator pkcs1v15CreatorPrivate = new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseSingleBlockCipher.Builder(provider, RSA.WRAP_PKCS1v1_5)
                    .withGeneralOperators(getGeneralEncryptionFactory(), getGeneralWrappingFactory())
                    .withPublicKeyConverter(publicKeyConverter)
                    .withPrivateKeyConverter(privateKeyConverter)
                    .setPrivateKeyOnly(true)
                    .withParametersCreatorProvider(new ParametersCreatorProvider()
                    {
                        public ParametersCreator get(final Parameters algorithm)
                        {
                            return new ParametersCreator()
                            {

                                public Parameters createParameters(boolean forEncryption, AlgorithmParameterSpec spec, SecureRandom random)
                                {
                                    return RSA.WRAP_PKCS1v1_5;
                                }
                            };
                        }
                    }).build();
            }
        });

        GuardedEngineCreator pkcs1v15CreatorPublic = new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseSingleBlockCipher.Builder(provider, RSA.WRAP_PKCS1v1_5)
                    .withGeneralOperators(getGeneralEncryptionFactory(), getGeneralWrappingFactory())
                    .withPublicKeyConverter(publicKeyConverter)
                    .withPrivateKeyConverter(privateKeyConverter)
                    .setPublicKeyOnly(true)
                    .withParametersCreatorProvider(new ParametersCreatorProvider()
                    {
                        public ParametersCreator get(final Parameters algorithm)
                        {
                            return new ParametersCreator()
                            {

                                public Parameters createParameters(boolean forEncryption, AlgorithmParameterSpec spec, SecureRandom random)
                                {
                                    return RSA.WRAP_PKCS1v1_5;
                                }
                            };
                        }
                    }).build();
            }
        });

        provider.addAlgorithmImplementation("Cipher.RSA", PREFIX + "CipherSpi$NoPadding", rsaCreator);
        provider.addAttributes("Cipher.RSA", generalRsaAttributes);

        if (!CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            provider.addAlgorithmImplementation("Cipher", PKCSObjectIdentifiers.rsaEncryption, PREFIX + "CipherSpi$PKCS1v1_5Padding", pkcs1v15Creator);
            provider.addAttributes("Cipher", PKCSObjectIdentifiers.rsaEncryption, generalRsaAttributes);
            provider.addAlgorithmImplementation("Cipher", X509ObjectIdentifiers.id_ea_rsa, PREFIX + "CipherSpi$PKCS1v1_5Padding", pkcs1v15Creator);
            provider.addAttributes("Cipher", X509ObjectIdentifiers.id_ea_rsa, generalRsaAttributes);

            provider.addAlgorithmImplementation("Cipher.RSA/1/PKCS1PADDING", PREFIX + "CipherSpi$PKCS1v1_5Padding_PrivateOnly", pkcs1v15CreatorPrivate);
            provider.addAlgorithmImplementation("Cipher.RSA/2/PKCS1PADDING", PREFIX + "CipherSpi$PKCS1v1_5Padding_PublicOnly", pkcs1v15CreatorPublic);
        }

        provider.addAlgorithmImplementation("Cipher", PKCSObjectIdentifiers.id_RSAES_OAEP, PREFIX + "CipherSpi$OAEPPadding", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                if (CryptoServicesRegistrar.isInApprovedOnlyMode())
                {
                    return new BaseSingleBlockCipher.Builder(provider, FipsRSA.WRAP_OAEP)
                        .withPublicKeyConverter(publicKeyConverter)
                        .withPrivateKeyConverter(privateKeyConverter)
                        .setWrapModeOnly(true)
                        .withParameters(new Class[]{OAEPParameterSpec.class})
                        .withFipsOperators(null, new FipsRSA.KeyWrapOperatorFactory())
                        .withParametersCreatorProvider(new ParametersCreatorProvider()
                        {
                            public ParametersCreator get(final Parameters algorithm)
                            {
                                return new ParametersCreator()
                                {

                                    public Parameters createParameters(boolean forEncryption, AlgorithmParameterSpec spec, SecureRandom random)
                                    {
                                        if (spec == null)
                                        {
                                            return FipsRSA.WRAP_OAEP;
                                        }

                                        return createFipsOaepParameters((OAEPParameterSpec)spec);
                                    }
                                };
                            }
                        }).build();
                }
                else
                {
                    return new BaseSingleBlockCipher.Builder(provider, RSA.WRAP_OAEP)
                        .withPublicKeyConverter(publicKeyConverter)
                        .withPrivateKeyConverter(privateKeyConverter)
                        .withParameters(new Class[]{OAEPParameterSpec.class})
                        .withGeneralOperators(getGeneralEncryptionFactory(), new RSA.KeyWrapOperatorFactory())
                        .withParametersCreatorProvider(new ParametersCreatorProvider()
                        {
                            public ParametersCreator get(final Parameters algorithm)
                            {
                                return new ParametersCreator()
                                {

                                    public Parameters createParameters(boolean forEncryption, AlgorithmParameterSpec spec, SecureRandom random)
                                        throws InvalidAlgorithmParameterException
                                    {
                                        if (spec == null)
                                        {
                                            return RSA.WRAP_OAEP;
                                        }

                                        if (!(spec instanceof OAEPParameterSpec))
                                        {
                                            throw new InvalidAlgorithmParameterException("OAEP can only accept OAEPParameterSpec");
                                        }

                                        OAEPParameterSpec oaepSpec = (OAEPParameterSpec)spec;
                                        DigestAlgorithm digest = Utils.digestNameToAlgMap.get(oaepSpec.getDigestAlgorithm());

                                        MGF1ParameterSpec mgfParams = (MGF1ParameterSpec)oaepSpec.getMGFParameters();
                                        DigestAlgorithm mgfDigest = Utils.digestNameToAlgMap.get(mgfParams.getDigestAlgorithm());

                                        return RSA.WRAP_OAEP.withDigest(digest).withMGFDigest(mgfDigest).withEncodingParams(((PSource.PSpecified)oaepSpec.getPSource()).getValue());
                                    }
                                };
                            }
                        }).build();
                }
            }
        });
        provider.addAttributes("Cipher", PKCSObjectIdentifiers.id_RSAES_OAEP, generalRsaAttributes);

        provider.addAlgorithmImplementation("KeyFactory.RSA", PREFIX + "KeyFactorySpi", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new RSAKeyFactory(getAlgorithmType());
            }
        });
        provider.addAlgorithmImplementation("KeyPairGenerator.RSA", PREFIX + "KeyPairGeneratorSpi", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new KeyPairGenerator(provider);
            }
        });

        AsymmetricKeyInfoConverter keyFact = new RSAKeyFactory(getAlgorithmType());

        registerOid(provider, PKCSObjectIdentifiers.rsaEncryption, "RSA", keyFact);
        registerOid(provider, X509ObjectIdentifiers.id_ea_rsa, "RSA", keyFact);

        registerOid(provider, PKCSObjectIdentifiers.id_RSAES_OAEP, "RSA", keyFact);
        registerOid(provider, PKCSObjectIdentifiers.id_RSASSA_PSS, "RSA", keyFact);
        registerOid(provider, PKCSObjectIdentifiers.id_rsa_KEM, "RSA", keyFact);

        provider.addAlgorithmImplementation("SecretKeyFactory.RSA-KAS-KEM", PREFIX + "RSAKTSKEM", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new KTSSKeyFactory(new ParametersCreator()
                {
                    public Parameters createParameters(boolean forEncryption, AlgorithmParameterSpec spec, SecureRandom random)
                        throws InvalidAlgorithmParameterException
                    {
                        InternalKtsSpec ktsSpec = (InternalKtsSpec)spec;

                        if (ktsSpec.parameterSpec != null)
                        {
                            throw new InvalidAlgorithmParameterException("RSA-KAS-KEM does not accept an AlgorithmParameterSpec");
                        }

                        return FipsRSA.KTS_SVE;
                    }
                }, provider, publicKeyConverter, privateKeyConverter);
            }
        });

        provider.addAlgorithmImplementation("SecretKeyFactory.RSA-KTS-KEM-KWS", PREFIX + "RSAKTSKEMKWS", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new KEMKTSSKeyFactory(provider);
            }
        });

        provider.addAlgorithmImplementation("Cipher.RSA-KTS-KEM-KWS", PREFIX + "CipherRSAKTSKEM", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
                throws NoSuchAlgorithmException
            {
                return new KtsCipherSpi(provider, "RSA-KTS-KEM-KWS");
            }
        });
        provider.addAttributes("Cipher.RSA-KTS-KEM-KWS", generalRsaAttributes);
        provider.addAlias("Cipher", "RSA-KTS-KEM-KWS", PKCSObjectIdentifiers.id_rsa_KEM);

        provider.addAlgorithmImplementation("AlgorithmParameters.RSA-KTS-KEM-KWS", PREFIX + "AlgParamsRSAKTSKEM", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
                throws NoSuchAlgorithmException
            {
                return new KtsAlgParams();
            }
        });
        provider.addAlias("AlgorithmParameters", "RSA-KTS-KEM-KWS", PKCSObjectIdentifiers.id_rsa_KEM);

        provider.addAlgorithmImplementation("SecretKeyFactory.RSA-KTS-OAEP", PREFIX + "RSAKTSOEAP", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new KTSSKeyFactory(new ParametersCreator()
                {

                    public Parameters createParameters(boolean forEncryption, AlgorithmParameterSpec spec, SecureRandom random)
                        throws InvalidAlgorithmParameterException
                    {
                        InternalKtsSpec ktsSpec = (InternalKtsSpec)spec;

                        if (ktsSpec.parameterSpec == null)
                        {
                            return FipsRSA.KTS_OAEP.withKeySizeInBits(ktsSpec.keySize).withMacKeySizeInBits(ktsSpec.macKeySize);
                        }

                        if (!(ktsSpec.parameterSpec instanceof OAEPParameterSpec))
                        {
                            throw new InvalidAlgorithmParameterException("KTS-OAEP can only accept OAEPParameterSpec");
                        }

                        OAEPParameterSpec oaepSpec = (OAEPParameterSpec)ktsSpec.parameterSpec;

                        return FipsRSA.KTS_OAEP.withOAEPParameters(createFipsOaepParameters(oaepSpec)).withKeySizeInBits(ktsSpec.keySize).withMacKeySizeInBits(ktsSpec.macKeySize);
                    }
                }, provider, publicKeyConverter, privateKeyConverter);
            }
        });

        provider.addAlgorithmImplementation("Signature.PSS", PREFIX + "PSSSignatureSpi$PSSwithRSA", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseSignature(provider, fipsRsaSigFactory, publicKeyConverter, privateKeyConverter, FipsRSA.PSS, PSSParameterSpec.DEFAULT);
            }
        });
        provider.addAttributes("Signature.PSS", generalRsaAttributes);
        provider.addAlias("Signature", "PSS", PKCSObjectIdentifiers.id_RSASSA_PSS);
        provider.addAlias("Signature", "PSS", "RSAPSS", "RSA-PSS");

        provider.addAlgorithmImplementation("Signature.NONEWITHRSA", PREFIX + "SignatureSpi$NONEwithRSA", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseSignature(provider, fipsRsaSigFactory, publicKeyConverter, privateKeyConverter, FipsRSA.PKCS1v1_5.withDigestAlgorithm(null));
            }
        });
        provider.addAttributes("Signature.NONEWITHRSA", generalRsaAttributes);
        provider.addAlias("Alg.Alias.Signature.RAWRSA", "NONEWITHRSA");

        addPSSSignature(provider, "SHA1", FipsSHS.Algorithm.SHA1, new PSSParameterSpec("SHA-1", "MGF1", new MGF1ParameterSpec("SHA-1"), 20, 1));
        addPSSSignature(provider, "SHA224", FipsSHS.Algorithm.SHA224, new PSSParameterSpec("SHA-224", "MGF1", new MGF1ParameterSpec("SHA-224"), 28, 1));
        addPSSSignature(provider, "SHA256", FipsSHS.Algorithm.SHA256, new PSSParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec("SHA-256"), 32, 1));
        addPSSSignature(provider, "SHA384", FipsSHS.Algorithm.SHA384, new PSSParameterSpec("SHA-384", "MGF1", new MGF1ParameterSpec("SHA-384"), 48, 1));
        addPSSSignature(provider, "SHA512", FipsSHS.Algorithm.SHA512, new PSSParameterSpec("SHA-512", "MGF1", new MGF1ParameterSpec("SHA-512"), 64, 1));
        addPSSSignature(provider, "SHA512(224)", FipsSHS.Algorithm.SHA512_224, new PSSParameterSpec("SHA-512(224)", "MGF1", new MGF1ParameterSpec("SHA-512(224)"), 28, 1));
        addPSSSignature(provider, "SHA512(256)", FipsSHS.Algorithm.SHA512_256, new PSSParameterSpec("SHA-512(256)", "MGF1", new MGF1ParameterSpec("SHA-512(256)"), 32, 1));


        addX931Signature(provider, "SHA1", FipsSHS.Algorithm.SHA1);
        addX931Signature(provider, "SHA224", FipsSHS.Algorithm.SHA224);
        addX931Signature(provider, "SHA256", FipsSHS.Algorithm.SHA256);
        addX931Signature(provider, "SHA384", FipsSHS.Algorithm.SHA384);
        addX931Signature(provider, "SHA512", FipsSHS.Algorithm.SHA512);
        addX931Signature(provider, "SHA512(224)", FipsSHS.Algorithm.SHA512_224);
        addX931Signature(provider, "SHA512(256)", FipsSHS.Algorithm.SHA512_256);

        if (!CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            addX931Signature(provider, "RIPEMD128", SecureHash.Algorithm.RIPEMD128);
            addX931Signature(provider, "RIPEMD160", SecureHash.Algorithm.RIPEMD160);
            addX931Signature(provider, "WHIRLPOOL", SecureHash.Algorithm.WHIRLPOOL);
        }

        if (!CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            addIso9796Signature(provider, "MD5", SecureHash.Algorithm.MD5);
            addIso9796Signature(provider, "SHA1", FipsSHS.Algorithm.SHA1);
            addIso9796Signature(provider, "SHA224", FipsSHS.Algorithm.SHA224);
            addIso9796Signature(provider, "SHA256", FipsSHS.Algorithm.SHA256);
            addIso9796Signature(provider, "SHA384", FipsSHS.Algorithm.SHA384);
            addIso9796Signature(provider, "SHA512", FipsSHS.Algorithm.SHA512);
            addIso9796Signature(provider, "SHA512(224)", FipsSHS.Algorithm.SHA512_224);
            addIso9796Signature(provider, "SHA512(256)", FipsSHS.Algorithm.SHA512_256);
            addIso9796Signature(provider, "RIPEMD128", SecureHash.Algorithm.RIPEMD128);
            addIso9796Signature(provider, "RIPEMD160", SecureHash.Algorithm.RIPEMD160);

            addIso9796PSSSignature(provider, "SHA1", FipsSHS.Algorithm.SHA1);
            addIso9796PSSSignature(provider, "SHA224", FipsSHS.Algorithm.SHA224);
            addIso9796PSSSignature(provider, "SHA256", FipsSHS.Algorithm.SHA256);
            addIso9796PSSSignature(provider, "SHA384", FipsSHS.Algorithm.SHA384);
            addIso9796PSSSignature(provider, "SHA512", FipsSHS.Algorithm.SHA512);
            addIso9796PSSSignature(provider, "SHA512(224)", FipsSHS.Algorithm.SHA512_224);
            addIso9796PSSSignature(provider, "SHA512(256)", FipsSHS.Algorithm.SHA512_256);
            addIso9796PSSSignature(provider, "RIPEMD128", SecureHash.Algorithm.RIPEMD128);
            addIso9796PSSSignature(provider, "RIPEMD160", SecureHash.Algorithm.RIPEMD160);
        }

        addDigestSignature(provider, FipsRSA.PKCS1v1_5.withDigestAlgorithm(FipsSHS.Algorithm.SHA1), "SHA1", PREFIX + "DigestSignatureSpi$SHA1", PKCSObjectIdentifiers.sha1WithRSAEncryption);

        provider.addAlias("Signature", "SHA1WITHRSA", OIWObjectIdentifiers.sha1WithRSA);

        addDigestSignature(provider, FipsRSA.PKCS1v1_5.withDigestAlgorithm(FipsSHS.Algorithm.SHA224), "SHA224", PREFIX + "DigestSignatureSpi$SHA224", PKCSObjectIdentifiers.sha224WithRSAEncryption);
        addDigestSignature(provider, FipsRSA.PKCS1v1_5.withDigestAlgorithm(FipsSHS.Algorithm.SHA256), "SHA256", PREFIX + "DigestSignatureSpi$SHA256", PKCSObjectIdentifiers.sha256WithRSAEncryption);
        addDigestSignature(provider, FipsRSA.PKCS1v1_5.withDigestAlgorithm(FipsSHS.Algorithm.SHA384), "SHA384", PREFIX + "DigestSignatureSpi$SHA384", PKCSObjectIdentifiers.sha384WithRSAEncryption);
        addDigestSignature(provider, FipsRSA.PKCS1v1_5.withDigestAlgorithm(FipsSHS.Algorithm.SHA512), "SHA512", PREFIX + "DigestSignatureSpi$SHA512", PKCSObjectIdentifiers.sha512WithRSAEncryption);
        addDigestSignature(provider, FipsRSA.PKCS1v1_5.withDigestAlgorithm(FipsSHS.Algorithm.SHA512_224), "SHA512(224)", PREFIX + "DigestSignatureSpi$SHA512_224", PKCSObjectIdentifiers.sha512_224WithRSAEncryption);
        addDigestSignature(provider, FipsRSA.PKCS1v1_5.withDigestAlgorithm(FipsSHS.Algorithm.SHA512_256), "SHA512(256)", PREFIX + "DigestSignatureSpi$SHA512_256", PKCSObjectIdentifiers.sha512_256WithRSAEncryption);

        if (!CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            addDigestSignature(provider, RSA.PKCS1v1_5.withDigestAlgorithm(SecureHash.Algorithm.MD5), "MD5", PREFIX + "DigestSignatureSpi$MD5", PKCSObjectIdentifiers.md5WithRSAEncryption);
            provider.addAlias("Signature", "MD5WITHRSA", OIWObjectIdentifiers.md5WithRSA);

            addDigestSignature(provider, RSA.PKCS1v1_5.withDigestAlgorithm(SecureHash.Algorithm.RIPEMD128), "RIPEMD128", PREFIX + "DigestSignatureSpi$RIPEMD128", TeleTrusTObjectIdentifiers.rsaSignatureWithripemd128);
            addDigestSignature(provider, RSA.PKCS1v1_5.withDigestAlgorithm(SecureHash.Algorithm.RIPEMD128), "RMD128", PREFIX + "DigestSignatureSpi$RIPEMD128", null);

            addDigestSignature(provider, RSA.PKCS1v1_5.withDigestAlgorithm(SecureHash.Algorithm.RIPEMD160), "RIPEMD160", PREFIX + "DigestSignatureSpi$RIPEMD160", TeleTrusTObjectIdentifiers.rsaSignatureWithripemd160);
            addDigestSignature(provider, RSA.PKCS1v1_5.withDigestAlgorithm(SecureHash.Algorithm.RIPEMD160), "RMD160", PREFIX + "DigestSignatureSpi$RIPEMD160", null);

            addDigestSignature(provider, RSA.PKCS1v1_5.withDigestAlgorithm(SecureHash.Algorithm.RIPEMD256), "RIPEMD256", PREFIX + "DigestSignatureSpi$RIPEMD256", TeleTrusTObjectIdentifiers.rsaSignatureWithripemd256);
            addDigestSignature(provider, RSA.PKCS1v1_5.withDigestAlgorithm(SecureHash.Algorithm.RIPEMD256), "RMD256", PREFIX + "DigestSignatureSpi$RIPEMD256", null);
        }
    }

    private void addPSSSignature(final BouncyCastleFipsProvider provider, String digestName, final Algorithm digest, final PSSParameterSpec pssSPec)
    {
        provider.addAlgorithmImplementation("Signature." + digestName + "WITHRSA/PSS", PREFIX + "PSSSignatureSpi$" + digestName, new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseSignature(provider, fipsRsaSigFactory, publicKeyConverter, privateKeyConverter, FipsRSA.PSS.withDigestAlgorithm((FipsDigestAlgorithm)digest), pssSPec);
            }
        });
        provider.addAttributes("Signature." + digestName + "WITHRSA/PSS", generalRsaAttributes);
        provider.addAlias("Signature", digestName + "WITHRSA/PSS", digestName + "WITHRSAANDMGF1");
        provider.addAlias("AlgorithmParameters", "PSS", digestName + "WITHRSA/PSS", digestName + "WITHRSAANDMGF1");
    }

    private void addX931Signature(final BouncyCastleFipsProvider provider, String digestName, final DigestAlgorithm digest)
    {
        if (digest instanceof FipsAlgorithm)
        {
            provider.addAlgorithmImplementation("Signature." + digestName + "WITHRSA/X9.31", PREFIX + "X931SignatureSpi$" + digestName, new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new BaseSignature(provider, fipsRsaSigFactory, publicKeyConverter, privateKeyConverter, FipsRSA.X931.withDigestAlgorithm((FipsDigestAlgorithm)digest));
                }
            });
        }
        else
        {
            provider.addAlgorithmImplementation("Signature." + digestName + "WITHRSA/X9.31", PREFIX + "X931SignatureSpi$" + digestName, new GuardedEngineCreator(new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new BaseSignature(provider, generalRsaSigFactory, publicKeyConverter, privateKeyConverter, new RSA.X931SignatureParameters(digest));
                }
            }));
        }
        provider.addAttributes("Signature." + digestName + "WITHRSA/X9.31", generalRsaAttributes);
    }

    private void addIso9796Signature(final BouncyCastleFipsProvider provider, String digestName, final DigestAlgorithm digest)
    {
        provider.addAlgorithmImplementation("Signature." + digestName + "WITHRSA/ISO9796-2", PREFIX + "ISO9796-2SignatureSpi$" + digestName, new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseSignature(provider, recoveryRsaSigFactory, publicKeyConverter, privateKeyConverter, RSA.ISO9796d2.withDigestAlgorithm(digest));
            }
        }));
        provider.addAttributes("Signature." + digestName + "WITHRSA/ISO9796-2", generalRsaAttributes);
    }

    private void addIso9796PSSSignature(final BouncyCastleFipsProvider provider, String digestName, final DigestAlgorithm digest)
    {
        provider.addAlgorithmImplementation("Signature." + digestName + "WITHRSA/ISO9796-2PSS", PREFIX + "ISO9796-2PSSSignatureSpi$" + digestName, new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseSignature(provider, recoveryRsaSigFactory, publicKeyConverter, privateKeyConverter, RSA.ISO9796d2PSS.withDigestAlgorithm(digest));
            }
        }));
        provider.addAttributes("Signature." + digestName + "WITHRSA/ISO9796-2PSS", generalRsaAttributes);
        provider.addAlias("Alg.Alias.Signature." + digestName + "WITHRSAANDMGF1/ISO9796-2", digestName + "WITHRSA/ISO9796-2PSS");
    }

    private void addDigestSignature(
        final BouncyCastleFipsProvider provider,
        final Parameters parameters,
        String digest,
        String className,
        ASN1ObjectIdentifier oid)
    {
        String mainName = digest + "WITHRSA";
        String alias = digest + "/" + "RSA";
        String longName = digest + "WITHRSAENCRYPTION";

        if (parameters instanceof FipsParameters)
        {
            provider.addAlgorithmImplementation("Signature." + mainName, className, new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new BaseSignature(provider, new AdaptiveSignatureOperatorFactory(), publicKeyConverter, privateKeyConverter, parameters);
                }
            });
        }
        else
        {
            provider.addAlgorithmImplementation("Signature." + mainName, className, new GuardedEngineCreator(new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new BaseSignature(provider, getGeneralSigFactory(), publicKeyConverter, privateKeyConverter, parameters);
                }
            }));
        }
        provider.addAttributes("Signature." + mainName, generalRsaAttributes);

        provider.addAlias("Signature", mainName, alias, longName);

        if (oid != null)
        {
            provider.addAlias("Signature", mainName, oid);
        }
    }

    private class AdaptiveSignatureOperatorFactory<T extends org.bouncycastle.crypto.Parameters>
        implements SignatureOperatorFactory<FipsRSA.PKCS1v15SignatureParameters>
    {
        public final OutputSigner createSigner(AsymmetricPrivateKey key, FipsRSA.PKCS1v15SignatureParameters parameters)
        {
            if (CryptoServicesRegistrar.isInApprovedOnlyMode())
            {
                return fipsRsaSigFactory.createSigner(key, parameters);
            }
            else
            {
                AsymmetricRSAPrivateKey k = (AsymmetricRSAPrivateKey)key;

                if (k.getModulus().bitLength() < 2048)
                {
                    RSA.PKCS1v15SignatureParameters params = RSA.PKCS1v1_5.withDigestAlgorithm(parameters.getDigestAlgorithm());

                    return getGeneralSigFactory().createSigner(key, params);
                }
                else
                {
                    return fipsRsaSigFactory.createSigner(key, parameters);
                }
            }
        }

        public final OutputVerifier createVerifier(AsymmetricPublicKey key, FipsRSA.PKCS1v15SignatureParameters parameters)
        {
            if (CryptoServicesRegistrar.isInApprovedOnlyMode())
            {
                return fipsRsaSigFactory.createVerifier(key, parameters);
            }
            else
            {
                AsymmetricRSAPublicKey k = (AsymmetricRSAPublicKey)key;

                if (k.getModulus().bitLength() < 1024)
                {
                    RSA.PKCS1v15SignatureParameters params = RSA.PKCS1v1_5.withDigestAlgorithm(parameters.getDigestAlgorithm());

                    return getGeneralSigFactory().createVerifier(key, params);
                }
                else
                {
                    return fipsRsaSigFactory.createVerifier(key, parameters);
                }
            }
        }
    }

    private static FipsRSA.OAEPParameters createFipsOaepParameters(OAEPParameterSpec spec)
    {
        OAEPParameterSpec oaepSpec = spec;
        FipsDigestAlgorithm digest = (FipsDigestAlgorithm)Utils.digestNameToAlgMap.get(oaepSpec.getDigestAlgorithm());

        MGF1ParameterSpec mgfParams = (MGF1ParameterSpec)oaepSpec.getMGFParameters();
        FipsDigestAlgorithm mgfDigest = (FipsDigestAlgorithm)Utils.digestNameToAlgMap.get(mgfParams.getDigestAlgorithm());

        return FipsRSA.WRAP_OAEP.withDigest(digest).withMGFDigest(mgfDigest).withEncodingParams(((PSource.PSpecified)oaepSpec.getPSource()).getValue());
    }

    static class InternalKtsSpec
        implements AlgorithmParameterSpec
    {

        private final int keySize;
        private final int macKeySize;
        private final AlgorithmParameterSpec parameterSpec;

        public InternalKtsSpec(int keySize, int macKeySize, AlgorithmParameterSpec parameterSpec)
        {
            this.keySize = keySize;
            this.macKeySize = macKeySize;
            this.parameterSpec = parameterSpec;
        }
    }

    static class KTSSKeyFactory
        extends SecretKeyFactorySpi
    {
        private final BouncyCastleFipsProvider fipsProvider;
        private final PublicKeyConverter publicKeyConverter;
        private final PrivateKeyConverter privateKeyConverter;
        private final ParametersCreator parametersCreator;

        public KTSSKeyFactory(ParametersCreator parametersCreator, BouncyCastleFipsProvider fipsProvider, PublicKeyConverter publicKeyConverter, PrivateKeyConverter privateKeyConverter)
        {
            this.parametersCreator = parametersCreator;
            this.fipsProvider = fipsProvider;
            this.publicKeyConverter = publicKeyConverter;
            this.privateKeyConverter = privateKeyConverter;
        }

        @Override
        protected SecretKey engineGenerateSecret(KeySpec keySpec)
            throws InvalidKeySpecException
        {
            FipsRSA.KTSOperatorFactory KTSOperatorFactory = new FipsRSA.KTSOperatorFactory(fipsProvider.getDefaultSecureRandom());
            try
            {
                if (keySpec instanceof KTSGenerateKeySpec)
                {
                    KTSGenerateKeySpec generateKeySpec = (KTSGenerateKeySpec)keySpec;
                    FipsRSA.KTSParameters parameters = (FipsRSA.KTSParameters)parametersCreator.createParameters(true, new InternalKtsSpec(generateKeySpec.getKeySize(), generateKeySpec.getMacKeySize(), generateKeySpec.getParameterSpec()), generateKeySpec.getSecureRandom());
                    EncapsulatingSecretGenerator secGen = KTSOperatorFactory.createGenerator(publicKeyConverter.convertKey(parameters.getAlgorithm(), generateKeySpec.getPublicKey()), parameters);

                    if (generateKeySpec.getSecureRandom() != null)
                    {
                        secGen = secGen.withSecureRandom(generateKeySpec.getSecureRandom());
                    }

                    try
                    {
                        SecretWithEncapsulation encSec = secGen.generate();
                        byte[] secret = encSec.getSecret();

                        if (generateKeySpec.getMacAlgorithmName() != null)
                        {
                            byte[] macKey = new byte[(generateKeySpec.getMacKeySize() + 7) / 8];
                            if (macKey.length > secret.length)
                            {
                                throw new InvalidKeySpecException("MAC key length larger than available key material");
                            }
                            byte[] tmp = new byte[secret.length - macKey.length];

                            System.arraycopy(secret, 0, macKey, 0, macKey.length);
                            System.arraycopy(secret, macKey.length, tmp, 0, tmp.length);

                            Arrays.fill(secret, (byte)0);

                            return new KTSKeyWithEncapsulation(new AgreedKeyWithMacKey(new SecretKeySpec(makeKeyBytes(parameters, generateKeySpec.getKdfAlgorithmId(), tmp, generateKeySpec.getKeySize(), generateKeySpec.getOtherInfo()), generateKeySpec.getKeyAlgorithmName()), generateKeySpec.getMacAlgorithmName(), macKey), encSec.getEncapsulation());
                        }

                        return new KTSKeyWithEncapsulation(new SecretKeySpec(makeKeyBytes(parameters, generateKeySpec.getKdfAlgorithmId(), secret, generateKeySpec.getKeySize(), generateKeySpec.getOtherInfo()), generateKeySpec.getKeyAlgorithmName()), encSec.getEncapsulation());
                    }
                    catch (PlainInputProcessingException e)
                    {
                        throw new InvalidKeySpecException("Unable to create secret: " + e.getMessage(), e);
                    }
                }
                if (keySpec instanceof KTSExtractKeySpec)
                {
                    KTSExtractKeySpec extractKeySpec = (KTSExtractKeySpec)keySpec;
                    FipsRSA.KTSParameters parameters = (FipsRSA.KTSParameters)parametersCreator.createParameters(true, new InternalKtsSpec(extractKeySpec.getKeySize(), extractKeySpec.getMacKeySize(), extractKeySpec.getParameterSpec()), null);
                    EncapsulatedSecretExtractor secExtract = KTSOperatorFactory.createExtractor(privateKeyConverter.convertKey(parameters.getAlgorithm(), extractKeySpec.getPrivateKey()), parameters);

                    byte[] encapsulation = extractKeySpec.getEncapsulation();
                    try
                    {
                        byte[] secret = secExtract.extractSecret(encapsulation, 0, encapsulation.length).getSecret();

                        if (extractKeySpec.getMacAlgorithmName() != null)
                        {
                            byte[] macKey = new byte[(extractKeySpec.getMacKeySize() + 7) / 8];
                            if (macKey.length > secret.length)
                            {
                                throw new InvalidKeySpecException("MAC key length larger than available key material");
                            }
                            byte[] tmp = new byte[secret.length - macKey.length];

                            System.arraycopy(secret, 0, macKey, 0, macKey.length);
                            System.arraycopy(secret, macKey.length, tmp, 0, tmp.length);

                            Arrays.fill(secret, (byte)0);

                            return new KTSKeyWithEncapsulation(new AgreedKeyWithMacKey(new SecretKeySpec(makeKeyBytes(parameters, extractKeySpec.getKdfAlgorithmId(), tmp, extractKeySpec.getKeySize(), extractKeySpec.getOtherInfo()), extractKeySpec.getKeyAlgorithmName()), extractKeySpec.getMacAlgorithmName(), macKey), encapsulation);
                        }

                        return new KTSKeyWithEncapsulation(new SecretKeySpec(makeKeyBytes(parameters, extractKeySpec.getKdfAlgorithmId(), secret, extractKeySpec.getKeySize(), extractKeySpec.getOtherInfo()), extractKeySpec.getKeyAlgorithmName()), encapsulation);
                    }
                    catch (InvalidCipherTextException e)
                    {
                        throw new InvalidKeySpecException("Unable to extract secret: " + e.getMessage(), e);
                    }
                }
            }
            catch (InvalidAlgorithmParameterException e)
            {
                throw new InvalidKeySpecException("Unable to process RSA key: " + e.getMessage(), e);
            }
            catch (InvalidKeyException e)
            {
                throw new InvalidKeySpecException("Unable to process RSA key: " + e.getMessage(), e);
            }
            catch (IllegalArgumentException e)
            {
                throw new InvalidKeySpecException("Unable to process KDF AlgorithmIdentifier: " + e.getMessage(), e);
            }

            throw new InvalidKeySpecException("Unknown KeySpec passed");
        }

        private byte[] makeKeyBytes(FipsRSA.KTSParameters parameters, AlgorithmIdentifier kdfAlgorithm, byte[] secret, int keyLength, byte[] otherInfo)
            throws InvalidKeySpecException
        {
            if (parameters instanceof FipsRSA.OAEPKTSParameters)
            {
                return secret;
            }

            AlgorithmIdentifier digAlg = AlgorithmIdentifier.getInstance(kdfAlgorithm.getParameters());
            if (Utils.isNotNull(digAlg.getParameters()))
            {
                throw new InvalidKeySpecException("Digest algorithm identifier cannot have parameters");
            }

            if (CryptoServicesRegistrar.isInApprovedOnlyMode())
            {
                if (otherInfo == null || otherInfo.length == 0)
                {
                    throw new FipsUnapprovedOperationError("OtherInfo/IV for KDF must be present in approved mode");
                }
            }

            KDFCalculator kdfCalculator;
            if (X9ObjectIdentifiers.id_kdf_kdf2.equals(kdfAlgorithm.getAlgorithm()))
            {
                kdfCalculator = new FipsKDF.AgreementOperatorFactory().createKDFCalculator(FipsKDF.X963.withPRF(getPrfAlgorithm(digAlg.getAlgorithm())).using(secret).withIV(otherInfo));
            }
            else if (X9ObjectIdentifiers.id_kdf_kdf3.equals(kdfAlgorithm.getAlgorithm()))
            {
                kdfCalculator = new FipsKDF.AgreementOperatorFactory().createKDFCalculator(FipsKDF.CONCATENATION.withPRF(getPrfAlgorithm(digAlg.getAlgorithm())).using(secret).withIV(otherInfo));
            }
            else
            {
                throw new InvalidKeySpecException("Unrecognized KDF: " + kdfAlgorithm.getAlgorithm());
            }

            byte[] keyBytes = new byte[(keyLength + 7) / 8];

            kdfCalculator.generateBytes(keyBytes);

            Arrays.fill(secret, (byte)0);

            return keyBytes;
        }

        private static FipsKDF.AgreementKDFPRF getPrfAlgorithm(ASN1ObjectIdentifier algorithm)
            throws InvalidKeySpecException
        {
            FipsKDF.AgreementKDFPRF prfAlg = kdfPRF.get(algorithm);

            if (prfAlg == null)
            {
                throw new InvalidKeySpecException("Unrecognized digest in KDF: " + algorithm);
            }

            return prfAlg;
        }

        @Override
        protected KeySpec engineGetKeySpec(SecretKey secretKey, Class aClass)
            throws InvalidKeySpecException
        {
            throw new InvalidKeySpecException("Operation not supported");
        }

        @Override
        protected SecretKey engineTranslateKey(SecretKey secretKey)
            throws InvalidKeyException
        {
            throw new InvalidKeyException("Operation not supported");
        }
    }

    static class KEMKTSSKeyFactory
        extends SecretKeyFactorySpi
    {
        private final BouncyCastleFipsProvider fipsProvider;

        public KEMKTSSKeyFactory(BouncyCastleFipsProvider fipsProvider)
        {
            this.fipsProvider = fipsProvider;
        }

        @Override
        protected SecretKey engineGenerateSecret(KeySpec keySpec)
            throws InvalidKeySpecException
        {
            try
            {
                if (keySpec instanceof KTSWithKEMKWSKeySpec)
                {
                    KTSWithKEMKWSKeySpec kemSpec = (KTSWithKEMKWSKeySpec)keySpec;
                    KTSKeySpec ktsSpec = kemSpec.getKTSKeySpec();
                    SecretKeyFactory keyFact = SecretKeyFactory.getInstance("RSA-KAS-KEM", fipsProvider);

                    if (ktsSpec instanceof KTSGenerateKeySpec)
                    {
                        KTSKeyWithEncapsulation ktsKey = (KTSKeyWithEncapsulation)keyFact.generateSecret(ktsSpec);
                        KeyGenerator keyGenerator = KeyGenerator.getInstance(kemSpec.getTransportedKeyAlgorithm(), fipsProvider);

                        keyGenerator.init(kemSpec.getTransportedKeySize(), ((KTSGenerateKeySpec)ktsSpec).getSecureRandom());

                        Cipher wrapCipher = Cipher.getInstance(ktsSpec.getKeyAlgorithmName(), fipsProvider);

                        wrapCipher.init(Cipher.WRAP_MODE, ktsKey, ((KTSGenerateKeySpec)ktsSpec).getSecureRandom());

                        SecretKey genKey = keyGenerator.generateKey();
                        ZeroizableSecretKey macKey = ktsKey.getMacKey();

                        byte[] encapsulation = Arrays.concatenate(ktsKey.getEncapsulation(), wrapCipher.wrap(genKey));
                        if (macKey != null)
                        {
                            return new KTSKeyWithEncapsulation(new AgreedKeyWithMacKey(genKey, macKey.getAlgorithm(), macKey.getEncoded()), encapsulation);
                        }
                        return new KTSKeyWithEncapsulation(genKey, encapsulation);
                    }
                    else
                    {
                        KTSExtractKeySpec extractKeySpec = (KTSExtractKeySpec)ktsSpec;
                        byte[] encapsulationPlusKey = extractKeySpec.getEncapsulation();
                        byte[] encapsulation = new byte[(((RSAPrivateKey)extractKeySpec.getPrivateKey()).getModulus().bitLength() + 7) / 8];

                        System.arraycopy(encapsulationPlusKey, 0, encapsulation, 0, encapsulation.length);

                        KTSExtractKeySpec internalSpec = new KTSExtractKeySpec.Builder(extractKeySpec.getPrivateKey(), encapsulation,
                                    extractKeySpec.getKeyAlgorithmName(), extractKeySpec.getKeySize(), extractKeySpec.getOtherInfo())
                            .withKdfAlgorithm(extractKeySpec.getKdfAlgorithmId())
                            .withMac(extractKeySpec.getMacAlgorithmName(), extractKeySpec.getMacKeySize())
                            .build();

                        KTSKeyWithEncapsulation ktsKey = (KTSKeyWithEncapsulation)keyFact.generateSecret(internalSpec);

                        Cipher wrapCipher = Cipher.getInstance(extractKeySpec.getKeyAlgorithmName(), fipsProvider);

                        wrapCipher.init(Cipher.UNWRAP_MODE, ktsKey);

                        byte[] encodedKey = new byte[encapsulationPlusKey.length - encapsulation.length];
                        System.arraycopy(encapsulationPlusKey, encapsulation.length, encodedKey, 0, encodedKey.length);

                        SecretKey transportedKey = (SecretKey)wrapCipher.unwrap(encodedKey, kemSpec.getTransportedKeyAlgorithm(), Cipher.SECRET_KEY);
                        ZeroizableSecretKey macKey = ktsKey.getMacKey();

                        int transportedKeyLength = transportedKey.getEncoded().length;
                        if (transportedKeyLength != (kemSpec.getTransportedKeySize() + 7) / 8)
                        {
                            throw new InvalidKeySpecException("KEM transported key the incorrect size: found " + transportedKeyLength + " bytes");
                        }
                        if (macKey != null)
                        {
                            return new KTSKeyWithEncapsulation(new AgreedKeyWithMacKey(transportedKey, macKey.getAlgorithm(), macKey.getEncoded()), encapsulation);
                        }
                        return new KTSKeyWithEncapsulation(transportedKey, encapsulation);
                    }
                }
            }
            catch (InvalidKeySpecException e)
            {
                throw e;
            }
            catch (GeneralSecurityException e)
            {
                throw new InvalidKeySpecException("Unable to process RSA key: " + e.getMessage(), e);
            }
            catch (IllegalArgumentException e)
            {
                throw new InvalidKeySpecException("Unable to process KDF AlgorithmIdentifier: " + e.getMessage(), e);
            }
            throw new InvalidKeySpecException("Unknown KeySpec passed");
        }

        @Override
        protected KeySpec engineGetKeySpec(SecretKey secretKey, Class aClass)
            throws InvalidKeySpecException
        {
            throw new InvalidKeySpecException("Operation not supported");
        }

        @Override
        protected SecretKey engineTranslateKey(SecretKey secretKey)
            throws InvalidKeyException
        {
            throw new InvalidKeyException("Operation not supported");
        }
    }

    static class RSAKeyFactory
        extends BaseKeyFactory
    {
        private final Algorithm algorithm;

        public RSAKeyFactory(Algorithm algorithm)
        {
            this.algorithm = algorithm;
        }

        protected KeySpec engineGetKeySpec(
            Key key,
            Class spec)
            throws InvalidKeySpecException
        {
            if (spec == null)
            {
                throw new InvalidKeySpecException("null spec is invalid");
            }

            if (spec.isAssignableFrom(RSAPublicKeySpec.class) && key instanceof RSAPublicKey)
            {
                RSAPublicKey k = (RSAPublicKey)key;

                return new RSAPublicKeySpec(k.getModulus(), k.getPublicExponent());
            }
            else if (spec.isAssignableFrom(RSAPrivateKeySpec.class) && key instanceof java.security.interfaces.RSAPrivateKey)
            {
                java.security.interfaces.RSAPrivateKey k = (java.security.interfaces.RSAPrivateKey)key;

                return new RSAPrivateKeySpec(k.getModulus(), k.getPrivateExponent());
            }
            else if (spec.isAssignableFrom(RSAPrivateCrtKeySpec.class) && key instanceof RSAPrivateCrtKey)
            {
                RSAPrivateCrtKey k = (RSAPrivateCrtKey)key;

                return new RSAPrivateCrtKeySpec(
                    k.getModulus(), k.getPublicExponent(),
                    k.getPrivateExponent(),
                    k.getPrimeP(), k.getPrimeQ(),
                    k.getPrimeExponentP(), k.getPrimeExponentQ(),
                    k.getCrtCoefficient());
            }

            return super.engineGetKeySpec(key, spec);
        }

        protected Key engineTranslateKey(
            Key key)
            throws InvalidKeyException
        {
            if (key instanceof PublicKey)
            {
                return new ProvRSAPublicKey(publicKeyConverter.convertKey(getAlgorithmType(), (PublicKey)key));
            }
            else if (key instanceof PrivateKey)
            {
                return toProviderKey(privateKeyConverter.convertKey(getAlgorithmType(), (PrivateKey)key));
            }

            if (key != null)
            {
                throw new InvalidKeyException("Key type unrecognized: " + key.getClass().getName());
            }

            throw new InvalidKeyException("Key is null");
        }

        protected PrivateKey engineGeneratePrivate(
            KeySpec keySpec)
            throws InvalidKeySpecException
        {
            if (keySpec instanceof PKCS8EncodedKeySpec)
            {
                PKCS8EncodedKeySpec pkcs8Spec = (PKCS8EncodedKeySpec)keySpec;
                try
                {
                    return generatePrivate(pkcs8Spec.getEncoded());
                }
                catch (Exception e)
                {
                    throw new InvalidKeySpecException(e.getMessage(), e);
                }
            }
            else if (keySpec instanceof RSAPrivateCrtKeySpec)
            {
                return new ProvRSAPrivateCrtKey(getAlgorithmType(), (RSAPrivateCrtKeySpec)keySpec);
            }
            else if (keySpec instanceof RSAPrivateKeySpec)
            {
                return new ProvRSAPrivateKey(getAlgorithmType(), (RSAPrivateKeySpec)keySpec);
            }
            else if (keySpec != null)
            {
                throw new InvalidKeySpecException("Unknown KeySpec type: " + keySpec.getClass().getName());
            }
            else
            {
                throw new InvalidKeySpecException("null keySpec passed for PrivateKey");
            }
        }

        protected PublicKey engineGeneratePublic(
            KeySpec keySpec)
            throws InvalidKeySpecException
        {
            if (keySpec instanceof RSAPublicKeySpec)
            {
                return new ProvRSAPublicKey(getAlgorithmType(), (RSAPublicKeySpec)keySpec);
            }

            return super.engineGeneratePublic(keySpec);
        }

        public PrivateKey generatePrivate(byte[] keyInfo)
            throws IOException
        {
            return generatePrivate(PrivateKeyInfo.getInstance(keyInfo));
        }

        public PrivateKey generatePrivate(PrivateKeyInfo keyInfo)
            throws IOException
        {
            return toProviderKey(new AsymmetricRSAPrivateKey(getAlgorithmType(), keyInfo));
        }

        public PublicKey generatePublic(SubjectPublicKeyInfo keyInfo)
            throws IOException
        {
            return new ProvRSAPublicKey(new AsymmetricRSAPublicKey(getAlgorithmType(), keyInfo));
        }

        private RSAPrivateKey toProviderKey(AsymmetricRSAPrivateKey rsaPrivateKey)
        {
            if (rsaPrivateKey.getP().equals(BigInteger.ZERO))
            {
                return new ProvRSAPrivateKey(rsaPrivateKey);
            }
            else
            {
                return new ProvRSAPrivateCrtKey(rsaPrivateKey);
            }
        }
    }

    private static Algorithm getAlgorithmType()
    {
        return CryptoServicesRegistrar.isInApprovedOnlyMode() ? FipsRSA.ALGORITHM : RSA.ALGORITHM;
    }

    private static String getMGFName(ASN1ObjectIdentifier mgfOid)
    {
        if (PKCSObjectIdentifiers.id_mgf1.equals(mgfOid))
        {
            return "MGF1";
        }

        return mgfOid.getId();
    }

    public static class OAEPAlgorithmParameters
        extends X509AlgorithmParameters
    {
        OAEPParameterSpec currentSpec;

        protected byte[] localGetEncoded()
            throws IOException
        {
            AlgorithmIdentifier hashAlgorithm = new AlgorithmIdentifier(
                DigestUtil.getOID(currentSpec.getDigestAlgorithm()),
                DERNull.INSTANCE);
            MGF1ParameterSpec mgfSpec = (MGF1ParameterSpec)currentSpec.getMGFParameters();
            AlgorithmIdentifier maskGenAlgorithm = new AlgorithmIdentifier(
                PKCSObjectIdentifiers.id_mgf1,
                new AlgorithmIdentifier(DigestUtil.getOID(mgfSpec.getDigestAlgorithm()), DERNull.INSTANCE));
            PSource.PSpecified pSource = (PSource.PSpecified)currentSpec.getPSource();
            AlgorithmIdentifier pSourceAlgorithm = new AlgorithmIdentifier(
                PKCSObjectIdentifiers.id_pSpecified, new DEROctetString(pSource.getValue()));
            RSAESOAEPparams oaepP = new RSAESOAEPparams(hashAlgorithm, maskGenAlgorithm, pSourceAlgorithm);

            return oaepP.getEncoded(ASN1Encoding.DER);
        }

        protected AlgorithmParameterSpec localEngineGetParameterSpec(
            Class paramSpec)
            throws InvalidParameterSpecException
        {
            if (paramSpec == OAEPParameterSpec.class || paramSpec == AlgorithmParameterSpec.class)
            {
                return currentSpec;
            }

            throw new InvalidParameterSpecException("AlgorithmParameterSpec not recognized: " + paramSpec.getName());
        }

        protected void engineInit(
            AlgorithmParameterSpec paramSpec)
            throws InvalidParameterSpecException
        {
            if (!(paramSpec instanceof OAEPParameterSpec))
            {
                throw new InvalidParameterSpecException("OAEPParameterSpec required to initialise an OAEP AlgorithmParameters object");
            }

            this.currentSpec = (OAEPParameterSpec)paramSpec;
        }

        protected void localInit(
            byte[] params)
            throws IOException
        {
            RSAESOAEPparams oaepP = RSAESOAEPparams.getInstance(params);

            currentSpec = new OAEPParameterSpec(
                MessageDigestUtils.getDigestName(oaepP.getHashAlgorithm().getAlgorithm()),
                getMGFName(oaepP.getMaskGenAlgorithm().getAlgorithm()),
                new MGF1ParameterSpec(MessageDigestUtils.getDigestName(AlgorithmIdentifier.getInstance(oaepP.getMaskGenAlgorithm().getParameters()).getAlgorithm())),
                new PSource.PSpecified(ASN1OctetString.getInstance(oaepP.getPSourceAlgorithm().getParameters()).getOctets()));
        }

        protected String engineToString()
        {
            return "OAEP Parameters";
        }
    }

    public static class PSSAlgorithmParameters
        extends X509AlgorithmParameters
    {
        PSSParameterSpec currentSpec;

        /**
         * Return the PKCS#1 ASN.1 structure RSASSA-PSS-params.
         */
        protected byte[] localGetEncoded()
            throws IOException
        {
            PSSParameterSpec pssSpec = currentSpec;
            AlgorithmIdentifier hashAlgorithm = new AlgorithmIdentifier(
                DigestUtil.getOID(pssSpec.getDigestAlgorithm()),
                DERNull.INSTANCE);
            MGF1ParameterSpec mgfSpec = (MGF1ParameterSpec)pssSpec.getMGFParameters();
            AlgorithmIdentifier maskGenAlgorithm = new AlgorithmIdentifier(
                PKCSObjectIdentifiers.id_mgf1,
                new AlgorithmIdentifier(DigestUtil.getOID(mgfSpec.getDigestAlgorithm()), DERNull.INSTANCE));
            RSASSAPSSparams pssP = new RSASSAPSSparams(hashAlgorithm, maskGenAlgorithm, new ASN1Integer(pssSpec.getSaltLength()), new ASN1Integer(pssSpec.getTrailerField()));

            return pssP.getEncoded("DER");
        }

        protected AlgorithmParameterSpec localEngineGetParameterSpec(
            Class paramSpec)
            throws InvalidParameterSpecException
        {
            if (paramSpec == PSSParameterSpec.class || paramSpec == AlgorithmParameterSpec.class)
            {
                return currentSpec;
            }

            throw new InvalidParameterSpecException("AlgorithmParameterSpec not recognized: " + paramSpec.getName());
        }

        protected void engineInit(
            AlgorithmParameterSpec paramSpec)
            throws InvalidParameterSpecException
        {
            if (!(paramSpec instanceof PSSParameterSpec))
            {
                throw new InvalidParameterSpecException("PSSParameterSpec required to initialise an PSS AlgorithmParameters object");
            }

            this.currentSpec = (PSSParameterSpec)paramSpec;
        }

        protected void localInit(
            byte[] params)
            throws IOException
        {
            RSASSAPSSparams pssP = RSASSAPSSparams.getInstance(params);

            currentSpec = new PSSParameterSpec(
                MessageDigestUtils.getDigestName(pssP.getHashAlgorithm().getAlgorithm()),
                getMGFName(pssP.getMaskGenAlgorithm().getAlgorithm()),
                new MGF1ParameterSpec(MessageDigestUtils.getDigestName(AlgorithmIdentifier.getInstance(pssP.getMaskGenAlgorithm().getParameters()).getAlgorithm())),
                pssP.getSaltLength().intValue(),
                pssP.getTrailerField().intValue());
        }

        protected String engineToString()
        {
            return "PSS Parameters";
        }
    }

    public static class KtsAlgParams
       extends X509AlgorithmParameters
    {
        private GenericHybridParameters params;

        @Override
        protected byte[] localGetEncoded()
            throws IOException
        {
            return params.getEncoded();
        }

        @Override
        protected void localInit(byte[] encoded)
            throws IOException
        {
            params = GenericHybridParameters.getInstance(encoded);
        }

        @Override
        protected AlgorithmParameterSpec localEngineGetParameterSpec(Class paramSpec)
            throws InvalidParameterSpecException
        {
            if (paramSpec == KTSParameterSpec.class || paramSpec == AlgorithmParameterSpec.class)
            {
                RsaKemParameters rsaKemParameters = RsaKemParameters.getInstance(params.getKem().getParameters());

                String keyAlg = wrapNames.get(params.getDem().getAlgorithm());
                if (keyAlg == null)
                {
                    keyAlg = params.getDem().getAlgorithm().getId();
                }
                return new KTSParameterSpec.Builder(keyAlg, rsaKemParameters.getKeyLength().intValue() * 8).withKdfAlgorithm(rsaKemParameters.getKeyDerivationFunction()).build();
            }

            throw new InvalidParameterSpecException("AlgorithmParameterSpec not recognized: " + paramSpec.getName());
        }

        @Override
        protected void engineInit(AlgorithmParameterSpec paramSpec)
            throws InvalidParameterSpecException
        {
            if (!(paramSpec instanceof KTSParameterSpec))
            {
                throw new InvalidParameterSpecException("KTSParameterSpec required to initialise a KTS AlgorithmParameters object");
            }

            KTSParameterSpec ktsParameterSpec = (KTSParameterSpec)paramSpec;
            int keySize = ktsParameterSpec.getKeySize();
            int keyLength = -1;
            ASN1ObjectIdentifier wrapOid = null;

            if (ktsParameterSpec.getKeyAlgorithmName().equalsIgnoreCase("AES"))
            {
                switch (keySize)
                {
                case 128:
                    wrapOid = NISTObjectIdentifiers.id_aes128_wrap;
                    keyLength = 16;
                    break;
                case 192:
                    wrapOid = NISTObjectIdentifiers.id_aes192_wrap;
                    keyLength = 24;
                    break;
                case 256:
                    wrapOid = NISTObjectIdentifiers.id_aes256_wrap;
                    keyLength = 32;
                    break;
                default:
                    throw new InvalidParameterSpecException("Unknown key size for AES: " + keySize);
                }
            }
            else if (ktsParameterSpec.getKeyAlgorithmName().equalsIgnoreCase("Camellia"))
            {
                switch (keySize)
                {
                case 128:
                    wrapOid = NTTObjectIdentifiers.id_camellia128_wrap;
                    keyLength = 16;
                    break;
                case 192:
                    wrapOid = NTTObjectIdentifiers.id_camellia192_wrap;
                    keyLength = 24;
                    break;
                case 256:
                    wrapOid = NTTObjectIdentifiers.id_camellia256_wrap;
                    keyLength = 32;
                    break;
                default:
                    throw new InvalidParameterSpecException("Unknown key size for Camellia: " + keySize);
                }
            }
            else
            {
                keyLength = keySizeProvider.getKeySize(ktsParameterSpec.getKeyAlgorithmName());
                try
                {
                    wrapOid = new ASN1ObjectIdentifier(ktsParameterSpec.getKeyAlgorithmName());
                }
                catch (IllegalArgumentException e)
                {
                    throw new InvalidParameterSpecException("Cannot recognise key algorithm: " + ktsParameterSpec.getKeyAlgorithmName());
                }
            }

            if (keyLength < 0)
            {
                throw new InvalidParameterSpecException("Unavailable key length for algorithm: " + ktsParameterSpec.getKeyAlgorithmName());
            }

            if (keyLength * 8 !=  keySize)
            {
                throw new InvalidParameterSpecException("Expected key size and key length do not match: " + keySize + " != (8 * " + keyLength + ")");
            }

            this.params = new GenericHybridParameters(
                new AlgorithmIdentifier(ISOIECObjectIdentifiers.id_kem_rsa, new RsaKemParameters(ktsParameterSpec.getKdfAlgorithm(), keyLength)),
                new AlgorithmIdentifier(wrapOid));
        }

        @Override
        protected String engineToString()
        {
            return "KTS AlgParams";
        }
    }

    static class KeyPairGenerator
        extends java.security.KeyPairGenerator
    {
        private final BouncyCastleFipsProvider fipsProvider;

        public KeyPairGenerator(
            BouncyCastleFipsProvider fipsProvider,
            String algorithmName)
        {
            super(algorithmName);
            this.fipsProvider = fipsProvider;
        }

        final static BigInteger defaultPublicExponent = BigInteger.valueOf(0x10001);

        AsymmetricKeyPairGenerator engine;

        public KeyPairGenerator(BouncyCastleFipsProvider fipsProvider)
        {
            this(fipsProvider, "RSA");
        }

        public void initialize(
            int strength)
        {
            initialize(strength, fipsProvider.getDefaultSecureRandom());
        }

        public void initialize(
            int strength,
            SecureRandom random)
        {
            if (strength < 2048)
            {
                engine = new RSA.KeyPairGenerator(new RSA.KeyGenParameters(defaultPublicExponent, strength), random);
            }
            else
            {
                engine = new FipsRSA.KeyPairGenerator(new FipsRSA.KeyGenParameters(defaultPublicExponent, strength), random);
            }
        }

        public void initialize(
            AlgorithmParameterSpec params)
            throws InvalidAlgorithmParameterException
        {
            initialize(params, fipsProvider.getDefaultSecureRandom());
        }

        public void initialize(
            AlgorithmParameterSpec params,
            SecureRandom random)
            throws InvalidAlgorithmParameterException
        {
            if (!(params instanceof RSAKeyGenParameterSpec))
            {
                throw new InvalidAlgorithmParameterException("AlgorithmParameterSpec not recognized: " + params.getClass().getName());
            }
            RSAKeyGenParameterSpec rsaParams = (RSAKeyGenParameterSpec)params;

            if (rsaParams.getKeysize() < 2048)
            {
                if (CryptoServicesRegistrar.isInApprovedOnlyMode())
                {
                    throw new InvalidAlgorithmParameterException("RSA key size too small for FIPS mode operation");
                }
                engine = new RSA.KeyPairGenerator(new RSA.KeyGenParameters(rsaParams.getPublicExponent(), rsaParams.getKeysize()), random);
            }
            else
            {
                engine = new FipsRSA.KeyPairGenerator(new FipsRSA.KeyGenParameters(rsaParams.getPublicExponent(), rsaParams.getKeysize()), random);
            }
        }

        public KeyPair generateKeyPair()
        {
            if (engine == null)
            {
                engine = new FipsRSA.KeyPairGenerator(new FipsRSA.KeyGenParameters(defaultPublicExponent, 2048), fipsProvider.getDefaultSecureRandom());
            }

            AsymmetricKeyPair pair = engine.generateKeyPair();
            AsymmetricRSAPublicKey pub = (AsymmetricRSAPublicKey)pair.getPublicKey();
            AsymmetricRSAPrivateKey priv = (AsymmetricRSAPrivateKey)pair.getPrivateKey();

            return new KeyPair(new ProvRSAPublicKey(pub), new ProvRSAPrivateCrtKey(priv));
        }
    }
}
