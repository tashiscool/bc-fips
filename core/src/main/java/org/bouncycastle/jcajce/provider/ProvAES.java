package org.bouncycastle.jcajce.provider;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEParameterSpec;

import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.asn1.cms.GCMParameters;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.crypto.AEADOperatorFactory;
import org.bouncycastle.crypto.AuthenticationParametersWithIV;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.Parameters;
import org.bouncycastle.crypto.ParametersWithIV;
import org.bouncycastle.crypto.PasswordBasedDeriver;
import org.bouncycastle.crypto.SymmetricKeyGenerator;
import org.bouncycastle.crypto.fips.FipsAES;
import org.bouncycastle.crypto.fips.FipsParameters;
import org.bouncycastle.crypto.fips.FipsSHS;
import org.bouncycastle.crypto.fips.FipsSecureRandom;
import org.bouncycastle.crypto.general.AES;
import org.bouncycastle.jcajce.spec.WrapParameterSpec;

final class ProvAES
    extends SymmetricAlgorithmProvider
{
    private static final Map<String, String> generalAesAttributes = new HashMap<String, String>();

    static
    {
        generalAesAttributes.put("SupportedKeyClasses", "javax.crypto.SecretKey");
        generalAesAttributes.put("SupportedKeyFormats", "RAW");
    }

    private static final String PREFIX = ProvAES.class.getName();

    private final FipsAES.OperatorFactory fipsOperatorFactory;
    private final FipsAES.AEADOperatorFactory fipsAeadOperatorFactory;
    private final FipsAES.KeyWrapOperatorFactory fipsKeyWrapOperatorFactory;

    private AES.OperatorFactory generalOperatorFactory;
    private AES.AEADOperatorFactory generalAeadOperatorFactory;
    private ParametersCreatorProvider<FipsParameters> fipsParametersCreatorProvider = new ParametersCreatorProvider<FipsParameters>()
    {
        public ParametersCreator get(final FipsParameters parameters)
        {
            if (Utils.isAuthMode(parameters.getAlgorithm()))
            {
                return new AuthParametersCreator((AuthenticationParametersWithIV)parameters);
            }
            else if (parameters.getAlgorithm().equals(FipsAES.KW.getAlgorithm()) || parameters.getAlgorithm().equals(FipsAES.KWP.getAlgorithm()))
            {
                return new ParametersCreator()
                {

                    public Parameters createParameters(boolean forEncryption, AlgorithmParameterSpec spec, SecureRandom random)
                        throws InvalidAlgorithmParameterException
                    {
                        if (spec instanceof WrapParameterSpec)
                        {
                            return ((FipsAES.WrapParameters)parameters).withUsingInverseFunction(((WrapParameterSpec)spec).useInverseFunction());
                        }

                        return parameters;
                    }
                };
            }

            return new IvParametersCreator((ParametersWithIV)parameters);
        }
    };
    private ParametersCreatorProvider<Parameters> generalParametersCreatorProvider = new ParametersCreatorProvider<Parameters>()
    {
        public ParametersCreator get(Parameters parameters)
        {
            if (Utils.isAuthMode(parameters.getAlgorithm()))
            {
                return new AuthParametersCreator((AuthenticationParametersWithIV)parameters);
            }

            return new IvParametersCreator((ParametersWithIV)parameters);
        }
    };

    public ProvAES()
    {
        fipsOperatorFactory = new FipsAES.OperatorFactory();
        fipsAeadOperatorFactory = new FipsAES.AEADOperatorFactory();
        fipsKeyWrapOperatorFactory = new FipsAES.KeyWrapOperatorFactory();

        if (!CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            generalOperatorFactory = new AES.OperatorFactory();
        }
    }

    private AES.OperatorFactory getGeneralOperatorFactory()
    {
        if (CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            return null;
        }

        if (generalOperatorFactory == null)
        {
            generalOperatorFactory = new AES.OperatorFactory();
        }

        return generalOperatorFactory;
    }

    private AEADOperatorFactory getGeneralAEADOperatorCreator()
    {
        if (CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            return null;
        }

        if (generalAeadOperatorFactory == null)
        {
            generalAeadOperatorFactory = new AES.AEADOperatorFactory();
        }

        return generalAeadOperatorFactory;
    }

    public void configure(final BouncyCastleFipsProvider provider)
    {
        final Class[] cipherSpecs = GcmSpecUtil.getCipherSpecClasses();
        final Class[] ivOnlySpec = new Class[]{IvParameterSpec.class};

        provider.addAlgorithmImplementation("AlgorithmParameters.AES", PREFIX + "$AlgParams", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new ASN1AlgorithmParameters("AES");
            }
        });
        provider.addAlias("AlgorithmParameters", "AES",
            NISTObjectIdentifiers.id_aes128_CBC, NISTObjectIdentifiers.id_aes192_CBC, NISTObjectIdentifiers.id_aes256_CBC,
            NISTObjectIdentifiers.id_aes128_CFB, NISTObjectIdentifiers.id_aes192_CFB, NISTObjectIdentifiers.id_aes256_CFB,
            NISTObjectIdentifiers.id_aes128_OFB, NISTObjectIdentifiers.id_aes192_OFB, NISTObjectIdentifiers.id_aes256_OFB);

        provider.addAlgorithmImplementation("AlgorithmParameters.GCM", PREFIX + "$AlgParamsGCM", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new ASN1AlgorithmParameters("GCM");
            }
        });
        provider.addAlias("AlgorithmParameters", "GCM",
            NISTObjectIdentifiers.id_aes128_GCM, NISTObjectIdentifiers.id_aes192_GCM, NISTObjectIdentifiers.id_aes256_GCM);

        provider.addAlgorithmImplementation("AlgorithmParameters.CCM", PREFIX + "$AlgParamsCCM", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new ASN1AlgorithmParameters("CCM");
            }
        });
        provider.addAlias("AlgorithmParameters", "CCM",
            NISTObjectIdentifiers.id_aes128_CCM, NISTObjectIdentifiers.id_aes192_CCM, NISTObjectIdentifiers.id_aes256_CCM);

        provider.addAlgorithmImplementation("AlgorithmParameterGenerator", NISTObjectIdentifiers.id_aes128_CBC, PREFIX + "$AlgParamGen", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new IVAlgorithmParameterGenerator(provider, "AES", 16);
            }
        });
        provider.addAlias("AlgorithmParameterGenerator", NISTObjectIdentifiers.id_aes128_CBC.getId(),
            NISTObjectIdentifiers.id_aes192_CBC, NISTObjectIdentifiers.id_aes256_CBC,
            NISTObjectIdentifiers.id_aes128_CFB, NISTObjectIdentifiers.id_aes192_CFB, NISTObjectIdentifiers.id_aes256_CFB,
            NISTObjectIdentifiers.id_aes128_OFB, NISTObjectIdentifiers.id_aes192_OFB, NISTObjectIdentifiers.id_aes256_OFB);

        provider.addAlgorithmImplementation("AlgorithmParameterGenerator.GCM", PREFIX + "$AlgParamGenGCM", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new AlgParamGenGCM(provider, "GCM", 128);
            }
        });
        provider.addAlias("AlgorithmParameterGenerator", "GCM",
            NISTObjectIdentifiers.id_aes128_GCM, NISTObjectIdentifiers.id_aes192_GCM, NISTObjectIdentifiers.id_aes256_GCM);


        provider.addAlgorithmImplementation("AlgorithmParameterGenerator.CCM", PREFIX + "$AlgParamGenCCM", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new AlgParamGenGCM(provider, "CCM", 64);
            }
        });
        provider.addAlias("AlgorithmParameterGenerator", "CCM",
            NISTObjectIdentifiers.id_aes128_CCM, NISTObjectIdentifiers.id_aes192_CCM, NISTObjectIdentifiers.id_aes256_CCM);

        provider.addAlgorithmImplementation("Cipher.AES", PREFIX + "$ECB", generalAesAttributes, new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {

                return new BaseCipher.Builder(provider, 128,
                    FipsAES.ECBwithPKCS7, FipsAES.ECB, FipsAES.ECBwithISO10126_2, FipsAES.ECBwithISO7816_4, FipsAES.ECBwithTBC,
                    FipsAES.ECBwithX923,
                    FipsAES.CBC, FipsAES.CBCwithPKCS7, FipsAES.CBCwithISO10126_2, FipsAES.CBCwithISO7816_4, FipsAES.CBCwithTBC,
                    FipsAES.CBCwithX923,
                    FipsAES.CFB128, FipsAES.CFB8, FipsAES.CBCwithCS1, FipsAES.CBCwithCS2, FipsAES.CBCwithCS3,
                    FipsAES.OFB,
                    FipsAES.CTR, FipsAES.GCM, FipsAES.CCM, FipsAES.CMAC,
                    AES.OCB, AES.EAX, AES.OpenPGPCFB)
                    .withFipsOperators(fipsParametersCreatorProvider, fipsOperatorFactory, fipsAeadOperatorFactory)
                    .withGeneralOperators(generalParametersCreatorProvider, getGeneralOperatorFactory(), getGeneralAEADOperatorCreator())
                    .withParameters(cipherSpecs).build();
            }
        });

        provider.addAlgorithmImplementation("Cipher", NISTObjectIdentifiers.id_aes128_ECB, PREFIX + "ECB128", generalAesAttributes, new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseCipher.Builder(provider, 128, FipsAES.ECBwithPKCS7)
                    .withFipsOperators(fipsParametersCreatorProvider, fipsOperatorFactory)
                    .withFixedKeySize(128).build();
            }
        });

        provider.addAlgorithmImplementation("Cipher", NISTObjectIdentifiers.id_aes192_ECB, PREFIX + "ECB192", generalAesAttributes, new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseCipher.Builder(provider, 128, FipsAES.ECBwithPKCS7)
                    .withFipsOperators(fipsParametersCreatorProvider, fipsOperatorFactory)
                    .withFixedKeySize(192).build();
            }
        });

        provider.addAlgorithmImplementation("Cipher", NISTObjectIdentifiers.id_aes256_ECB, PREFIX + "ECB256", generalAesAttributes, new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseCipher.Builder(provider, 128, FipsAES.ECBwithPKCS7)
                    .withFipsOperators(fipsParametersCreatorProvider, fipsOperatorFactory)
                    .withFixedKeySize(256).build();
            }
        });

        provider.addAlgorithmImplementation("Cipher", NISTObjectIdentifiers.id_aes128_CBC, PREFIX + "CBC128", generalAesAttributes, new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseCipher.Builder(provider, 128, FipsAES.CBCwithPKCS7)
                    .withParameters(ivOnlySpec)
                    .withFipsOperators(fipsParametersCreatorProvider, fipsOperatorFactory)
                    .withFixedKeySize(128).build();
            }
        });

        provider.addAlgorithmImplementation("Cipher", NISTObjectIdentifiers.id_aes192_CBC, PREFIX + "CBC192", generalAesAttributes, new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseCipher.Builder(provider, 128, FipsAES.CBCwithPKCS7)
                    .withParameters(ivOnlySpec)
                    .withFipsOperators(fipsParametersCreatorProvider, fipsOperatorFactory)
                    .withFixedKeySize(192).build();
            }
        });

        provider.addAlgorithmImplementation("Cipher", NISTObjectIdentifiers.id_aes256_CBC, PREFIX + "CBC256", generalAesAttributes, new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseCipher.Builder(provider, 128, FipsAES.CBCwithPKCS7)
                    .withParameters(ivOnlySpec)
                    .withFipsOperators(fipsParametersCreatorProvider, fipsOperatorFactory)
                    .withFixedKeySize(256).build();
            }
        });

        provider.addAlgorithmImplementation("Cipher", NISTObjectIdentifiers.id_aes128_OFB, PREFIX + "OFB128", generalAesAttributes, new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseCipher.Builder(provider, 128, FipsAES.OFB)
                    .withParameters(ivOnlySpec)
                    .withFipsOperators(fipsParametersCreatorProvider, fipsOperatorFactory)
                    .withFixedKeySize(128).build();
            }
        });

        provider.addAlgorithmImplementation("Cipher", NISTObjectIdentifiers.id_aes192_OFB, PREFIX + "OFB192", generalAesAttributes, new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseCipher.Builder(provider, 128, FipsAES.OFB)
                    .withParameters(ivOnlySpec)
                    .withFipsOperators(fipsParametersCreatorProvider, fipsOperatorFactory)
                    .withFixedKeySize(192).build();
            }
        });

        provider.addAlgorithmImplementation("Cipher", NISTObjectIdentifiers.id_aes256_OFB, PREFIX + "OFB256", generalAesAttributes, new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseCipher.Builder(provider, 128, FipsAES.OFB)
                    .withParameters(ivOnlySpec)
                    .withFipsOperators(fipsParametersCreatorProvider, fipsOperatorFactory)
                    .withFixedKeySize(256).build();
            }
        });

        provider.addAlgorithmImplementation("Cipher", NISTObjectIdentifiers.id_aes128_CFB, PREFIX + "CFB128", generalAesAttributes, new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseCipher.Builder(provider, 128, FipsAES.CFB128)
                    .withParameters(ivOnlySpec)
                    .withFipsOperators(fipsParametersCreatorProvider, fipsOperatorFactory)
                    .withFixedKeySize(128).build();
            }
        });

        provider.addAlgorithmImplementation("Cipher", NISTObjectIdentifiers.id_aes192_CFB, PREFIX + "CFB192", generalAesAttributes, new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseCipher.Builder(provider, 128, FipsAES.CFB128)
                    .withParameters(ivOnlySpec)
                    .withFipsOperators(fipsParametersCreatorProvider, fipsOperatorFactory)
                    .withFixedKeySize(192).build();
            }
        });

        provider.addAlgorithmImplementation("Cipher", NISTObjectIdentifiers.id_aes256_CFB, PREFIX + "CFB256", generalAesAttributes, new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseCipher.Builder(provider, 128, FipsAES.CFB128)
                    .withParameters(ivOnlySpec)
                    .withFipsOperators(fipsParametersCreatorProvider, fipsOperatorFactory)
                    .withFixedKeySize(256).build();
            }
        });

        provider.addAlgorithmImplementation("Cipher.AESWRAP", PREFIX + "$Wrap", generalAesAttributes,
            new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new BaseWrapCipher.Builder(provider, FipsAES.KW).withFipsOperators(fipsParametersCreatorProvider, fipsKeyWrapOperatorFactory).withParameters(new Class[]{WrapParameterSpec.class}).build();
                }
            });
        provider.addAlias("Alg.Alias.Cipher.AESKW", "AESWRAP");

        if (!CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            provider.addAlgorithmImplementation("Cipher.AESRFC3211WRAP", PREFIX + "$RFC3211Wrap", generalAesAttributes, new GuardedEngineCreator(
                new EngineCreator()
                {
                    public Object createInstance(Object constructorParameter)
                    {
                        return new BaseWrapCipher.Builder(provider, AES.RFC3211_WRAP).withGeneralOperators(generalParametersCreatorProvider, new AES.KeyWrapOperatorFactory()).withParameters(ivOnlySpec).build();
                    }
                }));
        }

        provider.addAlgorithmImplementation("Cipher", NISTObjectIdentifiers.id_aes128_wrap, PREFIX + "$WRAP128", generalAesAttributes, new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseWrapCipher.Builder(provider, FipsAES.KW)
                    .withFipsOperators(fipsParametersCreatorProvider, fipsKeyWrapOperatorFactory)
                    .withParameters(new Class[]{WrapParameterSpec.class})
                    .withFixedKeySize(128).build();
            }
        });
        provider.addAlgorithmImplementation("Cipher", NISTObjectIdentifiers.id_aes192_wrap, PREFIX + "$WRAP192", generalAesAttributes, new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseWrapCipher.Builder(provider, FipsAES.KW)
                    .withFipsOperators(fipsParametersCreatorProvider, fipsKeyWrapOperatorFactory)
                    .withParameters(new Class[]{WrapParameterSpec.class})
                    .withFixedKeySize(192).build();
            }
        });
        provider.addAlgorithmImplementation("Cipher", NISTObjectIdentifiers.id_aes256_wrap, PREFIX + "$WRAP256", generalAesAttributes, new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseWrapCipher.Builder(provider, FipsAES.KW)
                    .withFipsOperators(fipsParametersCreatorProvider, fipsKeyWrapOperatorFactory)
                    .withParameters(new Class[]{WrapParameterSpec.class})
                    .withFixedKeySize(256).build();
            }
        });

        provider.addAlgorithmImplementation("Cipher", NISTObjectIdentifiers.id_aes128_wrap_pad, PREFIX + "$WRAPPAD128", generalAesAttributes, new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseWrapCipher.Builder(provider, FipsAES.KWP)
                    .withFipsOperators(fipsParametersCreatorProvider, fipsKeyWrapOperatorFactory)
                    .withParameters(new Class[]{WrapParameterSpec.class})
                    .withFixedKeySize(128).build();
            }
        });
        provider.addAlgorithmImplementation("Cipher", NISTObjectIdentifiers.id_aes192_wrap_pad, PREFIX + "$WRAPPAD192", generalAesAttributes, new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseWrapCipher.Builder(provider, FipsAES.KWP)
                    .withFipsOperators(fipsParametersCreatorProvider, fipsKeyWrapOperatorFactory)
                    .withParameters(new Class[]{WrapParameterSpec.class})
                    .withFixedKeySize(192).build();
            }
        });
        provider.addAlgorithmImplementation("Cipher", NISTObjectIdentifiers.id_aes256_wrap_pad, PREFIX + "$WRAPPAD256", generalAesAttributes, new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseWrapCipher.Builder(provider, FipsAES.KWP)
                    .withFipsOperators(fipsParametersCreatorProvider, fipsKeyWrapOperatorFactory)
                    .withParameters(new Class[]{WrapParameterSpec.class})
                    .withFixedKeySize(256).build();
            }
        });

        provider.addAlgorithmImplementation("Cipher.AESWRAPPAD", PREFIX + "$WrapWithPad", generalAesAttributes,
            new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new BaseWrapCipher.Builder(provider, FipsAES.KWP).withFipsOperators(fipsParametersCreatorProvider, fipsKeyWrapOperatorFactory).withParameters(new Class[]{WrapParameterSpec.class}).build();
                }
            });
        provider.addAlias("Cipher", "AESWRAPPAD", "AESKWP");

        provider.addAlgorithmImplementation("Cipher.GCM", PREFIX + "$GCM", generalAesAttributes, new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseCipher.Builder(provider, 128, FipsAES.GCM)
                    .withParameters(cipherSpecs)
                    .withFipsOperators(fipsParametersCreatorProvider, null, fipsAeadOperatorFactory)
                    .build();
            }
        });
        provider.addAlgorithmImplementation("Cipher", NISTObjectIdentifiers.id_aes128_GCM, PREFIX + "$GCM128", generalAesAttributes, new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseCipher.Builder(provider, 128, FipsAES.GCM)
                    .withParameters(cipherSpecs)
                    .withFipsOperators(fipsParametersCreatorProvider, null, fipsAeadOperatorFactory)
                    .withFixedKeySize(128).build();
            }
        });
        provider.addAlgorithmImplementation("Cipher", NISTObjectIdentifiers.id_aes192_GCM, PREFIX + "$GCM192", generalAesAttributes, new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseCipher.Builder(provider, 128, FipsAES.GCM)
                    .withParameters(cipherSpecs)
                    .withFipsOperators(fipsParametersCreatorProvider, null, fipsAeadOperatorFactory)
                    .withFixedKeySize(192).build();
            }
        });
        provider.addAlgorithmImplementation("Cipher", NISTObjectIdentifiers.id_aes256_GCM, PREFIX + "$GCM256", generalAesAttributes, new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseCipher.Builder(provider, 128, FipsAES.GCM)
                    .withParameters(cipherSpecs)
                    .withFipsOperators(fipsParametersCreatorProvider, null, fipsAeadOperatorFactory)
                    .withFixedKeySize(256).build();
            }
        });

        provider.addAlgorithmImplementation("Cipher.CCM", PREFIX + "$CCM", generalAesAttributes, new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseCipher.Builder(provider, 128, FipsAES.CCM)
                    .withParameters(cipherSpecs)
                    .withFipsOperators(fipsParametersCreatorProvider, null, fipsAeadOperatorFactory)
                    .build();
            }
        });
        provider.addAlgorithmImplementation("Cipher", NISTObjectIdentifiers.id_aes128_CCM, PREFIX + "$CCM128", generalAesAttributes, new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseCipher.Builder(provider, 128, FipsAES.CCM)
                    .withParameters(cipherSpecs)
                    .withFipsOperators(fipsParametersCreatorProvider, null, fipsAeadOperatorFactory)
                    .withFixedKeySize(128).build();
            }
        });
        provider.addAlgorithmImplementation("Cipher", NISTObjectIdentifiers.id_aes192_CCM, PREFIX + "$CCM192", generalAesAttributes, new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseCipher.Builder(provider, 128, FipsAES.CCM)
                    .withParameters(cipherSpecs)
                    .withFipsOperators(fipsParametersCreatorProvider, null, fipsAeadOperatorFactory)
                    .withFixedKeySize(192).build();
            }
        });
        provider.addAlgorithmImplementation("Cipher", NISTObjectIdentifiers.id_aes256_CCM, PREFIX + "$CCM256", generalAesAttributes, new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseCipher.Builder(provider, 128, FipsAES.CCM)
                    .withParameters(cipherSpecs)
                    .withFipsOperators(fipsParametersCreatorProvider, null, fipsAeadOperatorFactory)
                    .withFixedKeySize(256).build();
            }
        });

        provider.addAlgorithmImplementation("KeyGenerator.AES", PREFIX + "$KeyGen",
            new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new BaseKeyGenerator(provider, "AES", 128, new KeyGeneratorCreator()
                    {
                        public SymmetricKeyGenerator createInstance(int keySize, SecureRandom random)
                        {
                            return new FipsAES.KeyGenerator(keySize, random);
                        }
                    });
                }
            });
        provider.addAlias("KeyGenerator", "AES", NISTObjectIdentifiers.aes);

        EngineCreator aes128KeyGenCreator = new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseKeyGenerator(provider, "AES", 128, true, new KeyGeneratorCreator()
                {
                    public SymmetricKeyGenerator createInstance(int keySize, SecureRandom random)
                    {
                        return new FipsAES.KeyGenerator(128, random);
                    }
                });
            }
        };

        addKeyGeneratorForOIDs(provider, PREFIX, aes128KeyGenCreator,
            NISTObjectIdentifiers.id_aes128_ECB, NISTObjectIdentifiers.id_aes128_CBC, NISTObjectIdentifiers.id_aes128_OFB,
            NISTObjectIdentifiers.id_aes128_CFB, NISTObjectIdentifiers.id_aes128_GCM, NISTObjectIdentifiers.id_aes128_CCM,
            NISTObjectIdentifiers.id_aes128_wrap);

        EngineCreator aes192KeyGenCreator = new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseKeyGenerator(provider, "AES", 192, true, new KeyGeneratorCreator()
                {
                    public SymmetricKeyGenerator createInstance(int keySize, SecureRandom random)
                    {
                        return new FipsAES.KeyGenerator(192, random);
                    }
                });
            }
        };
        addKeyGeneratorForOIDs(provider, PREFIX, aes192KeyGenCreator,
            NISTObjectIdentifiers.id_aes192_ECB, NISTObjectIdentifiers.id_aes192_CBC, NISTObjectIdentifiers.id_aes192_OFB,
            NISTObjectIdentifiers.id_aes192_CFB, NISTObjectIdentifiers.id_aes192_GCM, NISTObjectIdentifiers.id_aes192_CCM,
            NISTObjectIdentifiers.id_aes192_wrap);

        EngineCreator aes256KeyGenCreator = new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseKeyGenerator(provider, "AES", 256, true, new KeyGeneratorCreator()
                {
                    public SymmetricKeyGenerator createInstance(int keySize, SecureRandom random)
                    {
                        return new FipsAES.KeyGenerator(256, random);
                    }
                });
            }
        };
        addKeyGeneratorForOIDs(provider, PREFIX, aes256KeyGenCreator,
            NISTObjectIdentifiers.id_aes256_ECB, NISTObjectIdentifiers.id_aes256_CBC, NISTObjectIdentifiers.id_aes256_OFB,
            NISTObjectIdentifiers.id_aes256_CFB, NISTObjectIdentifiers.id_aes256_GCM, NISTObjectIdentifiers.id_aes256_CCM,
            NISTObjectIdentifiers.id_aes256_wrap);

        provider.addAlgorithmImplementation("SecretKeyFactory.AES", PREFIX + "$AESKFACT", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseSecretKeyFactory("AES", FipsAES.ALGORITHM, new BaseSecretKeyFactory.Validator()
                {
                    public byte[] validated(byte[] keyBytes)
                        throws InvalidKeySpecException
                    {
                        int size = keyBytes.length * 8;
                        if (size != 128 && size != 192 && size != 256)
                        {
                            throw new InvalidKeySpecException("Provided key data wrong size for AES");
                        }

                        return keyBytes;
                    }
                });
            }
        });
        provider.addAlias("SecretKeyFactory", "AES", NISTObjectIdentifiers.aes);

        if (!CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            provider.addAlgorithmImplementation("Cipher.PBEWITHSHAAND128BITAES-BC", PREFIX + "$PBEWithAES126CBC", new GuardedEngineCreator(new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new BaseCipher.Builder(provider, 128, FipsAES.CBCwithPKCS7)
                        .withFixedKeySize(128)
                        .withScheme(PBEScheme.PKCS12)
                        .withFipsOperators(fipsParametersCreatorProvider, fipsOperatorFactory, null)
                        .withParameters(new Class[]{PBEParameterSpec.class}).build();
                }
            }));
            provider.addAlgorithmImplementation("Cipher.PBEWITHSHAAND192BITAES-BC", PREFIX + "$PBEWithAES192CBC", new GuardedEngineCreator(new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new BaseCipher.Builder(provider, 128, FipsAES.CBCwithPKCS7)
                        .withFixedKeySize(192)
                        .withScheme(PBEScheme.PKCS12)
                        .withFipsOperators(fipsParametersCreatorProvider, fipsOperatorFactory, null)
                        .withParameters(new Class[]{PBEParameterSpec.class}).build();
                }
            }));
            provider.addAlgorithmImplementation("Cipher.PBEWITHSHAAND256BITAES-BC", PREFIX + "$PBEWithAES256CBC", new GuardedEngineCreator(new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new BaseCipher.Builder(provider, 128, FipsAES.CBCwithPKCS7)
                        .withFixedKeySize(256)
                        .withScheme(PBEScheme.PKCS12)
                        .withFipsOperators(fipsParametersCreatorProvider, fipsOperatorFactory, null)
                        .withParameters(new Class[]{PBEParameterSpec.class}).build();
                }
            }));

            provider.addAlgorithmImplementation("Cipher.PBEWITHSHA256AND128BITAES-BC", PREFIX + "$PBESHA256WithAES126CBC", new GuardedEngineCreator(new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new BaseCipher.Builder(provider, 128, FipsAES.CBCwithPKCS7)
                        .withFixedKeySize(128)
                        .withScheme(PBEScheme.PKCS12)
                        .withPrf(FipsSHS.Algorithm.SHA256)
                        .withFipsOperators(fipsParametersCreatorProvider, fipsOperatorFactory, null)
                        .withParameters(new Class[]{PBEParameterSpec.class}).build();
                }
            }));
            provider.addAlgorithmImplementation("Cipher.PBEWITHSHA256AND192BITAES-BC", PREFIX + "$PBESHA256WithAES192CBC", new GuardedEngineCreator(new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new BaseCipher.Builder(provider, 128, FipsAES.CBCwithPKCS7)
                        .withFixedKeySize(192)
                        .withScheme(PBEScheme.PKCS12)
                        .withPrf(FipsSHS.Algorithm.SHA256)
                        .withFipsOperators(fipsParametersCreatorProvider, fipsOperatorFactory, null)
                        .withParameters(new Class[]{PBEParameterSpec.class}).build();
                }
            }));
            provider.addAlgorithmImplementation("Cipher.PBEWITHSHA256AND256BITAES-BC", PREFIX + "$PBESHA256WithAES256CBC", new GuardedEngineCreator(new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new BaseCipher.Builder(provider, 128, FipsAES.CBCwithPKCS7)
                        .withFixedKeySize(256)
                        .withScheme(PBEScheme.PKCS12)
                        .withPrf(FipsSHS.Algorithm.SHA256)
                        .withFipsOperators(fipsParametersCreatorProvider, fipsOperatorFactory, null)
                        .withParameters(new Class[]{PBEParameterSpec.class}).build();
                }
            }));

            provider.addAlias("Cipher", "PBEWITHSHAAND128BITAES-BC", BCObjectIdentifiers.bc_pbe_sha1_pkcs12_aes128_cbc);
            provider.addAlias("Cipher", "PBEWITHSHAAND192BITAES-BC", BCObjectIdentifiers.bc_pbe_sha1_pkcs12_aes192_cbc);
            provider.addAlias("Cipher", "PBEWITHSHAAND256BITAES-BC", BCObjectIdentifiers.bc_pbe_sha1_pkcs12_aes256_cbc);
            provider.addAlias("Cipher", "PBEWITHSHA256AND128BITAES-BC", BCObjectIdentifiers.bc_pbe_sha256_pkcs12_aes128_cbc);
            provider.addAlias("Cipher", "PBEWITHSHA256AND192BITAES-BC", BCObjectIdentifiers.bc_pbe_sha256_pkcs12_aes192_cbc);
            provider.addAlias("Cipher", "PBEWITHSHA256AND256BITAES-BC", BCObjectIdentifiers.bc_pbe_sha256_pkcs12_aes256_cbc);

            provider.addAlias("Cipher", "PBEWITHSHAAND128BITAES-BC", "PBEWITHSHA1AND128BITAES-BC", "PBEWITHSHA-1AND128BITAES-BC");
            provider.addAlias("Cipher", "PBEWITHSHAAND192BITAES-BC", "PBEWITHSHA1AND192BITAES-BC", "PBEWITHSHA-1AND192BITAES-BC");
            provider.addAlias("Cipher", "PBEWITHSHAAND256BITAES-BC", "PBEWITHSHA1AND256BITAES-BC", "PBEWITHSHA-1AND256BITAES-BC");

            provider.addAlias("Cipher", "PBEWITHSHA256AND128BITAES-BC", "PBEWITHSHA-256AND128BITAES-BC");
            provider.addAlias("Cipher", "PBEWITHSHA256AND192BITAES-BC", "PBEWITHSHA-256AND192BITAES-BC");
            provider.addAlias("Cipher", "PBEWITHSHA256AND256BITAES-BC", "PBEWITHSHA-256AND256BITAES-BC");

            provider.addAlgorithmImplementation("SecretKeyFactory.PBEWITHSHAAND128BITAES-BC", PREFIX + "$PBEWithSHAAnd128BitAESBC", new GuardedEngineCreator(new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new ProvPKCS12.KeyFactory("AES", PasswordBasedDeriver.KeyType.CIPHER, 128);
                }
            }));
            provider.addAlgorithmImplementation("SecretKeyFactory.PBEWITHSHAAND192BITAES-BC", PREFIX + "$PBEWithSHAAnd192BitAESBC", new GuardedEngineCreator(new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new ProvPKCS12.KeyFactory("AES", PasswordBasedDeriver.KeyType.CIPHER, 192);
                }
            }));
            provider.addAlgorithmImplementation("SecretKeyFactory.PBEWITHSHAAND256BITAES-BC", PREFIX + "$PBEWithSHAAnd256BitAESBC", new GuardedEngineCreator(new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new ProvPKCS12.KeyFactory("AES", PasswordBasedDeriver.KeyType.CIPHER, 256);
                }
            }));

            provider.addAlgorithmImplementation("SecretKeyFactory.PBEWITHSHA256AND128BITAES-BC", PREFIX + "$PBEWithSHA256And128BitAESBC", new GuardedEngineCreator(new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new ProvPKCS12.KeyFactory("AES", FipsSHS.Algorithm.SHA256, PasswordBasedDeriver.KeyType.CIPHER, 128);
                }
            }));
            provider.addAlgorithmImplementation("SecretKeyFactory.PBEWITHSHA256AND192BITAES-BC", PREFIX + "$PBEWithSHA256And192BitAESBC", new GuardedEngineCreator(new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new ProvPKCS12.KeyFactory("AES", FipsSHS.Algorithm.SHA256, PasswordBasedDeriver.KeyType.CIPHER, 192);
                }
            }));
            provider.addAlgorithmImplementation("SecretKeyFactory.PBEWITHSHA256AND256BITAES-BC", PREFIX + "$PBEWithSHA256And256BitAESBC", new GuardedEngineCreator(new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new ProvPKCS12.KeyFactory("AES", FipsSHS.Algorithm.SHA256, PasswordBasedDeriver.KeyType.CIPHER, 256);
                }
            }));

            provider.addAlias("Alg.Alias.SecretKeyFactory.PBEWITHSHA1AND128BITAES-BC", "PBEWITHSHAAND128BITAES-BC");
            provider.addAlias("Alg.Alias.SecretKeyFactory.PBEWITHSHA1AND192BITAES-BC", "PBEWITHSHAAND192BITAES-BC");
            provider.addAlias("Alg.Alias.SecretKeyFactory.PBEWITHSHA1AND256BITAES-BC", "PBEWITHSHAAND256BITAES-BC");
            provider.addAlias("Alg.Alias.SecretKeyFactory.PBEWITHSHA-1AND128BITAES-BC", "PBEWITHSHAAND128BITAES-BC");
            provider.addAlias("Alg.Alias.SecretKeyFactory.PBEWITHSHA-1AND192BITAES-BC", "PBEWITHSHAAND192BITAES-BC");
            provider.addAlias("Alg.Alias.SecretKeyFactory.PBEWITHSHA-1AND256BITAES-BC", "PBEWITHSHAAND256BITAES-BC");
            provider.addAlias("Alg.Alias.SecretKeyFactory.PBEWITHSHA-256AND128BITAES-BC", "PBEWITHSHA256AND128BITAES-BC");
            provider.addAlias("Alg.Alias.SecretKeyFactory.PBEWITHSHA-256AND192BITAES-BC", "PBEWITHSHA256AND192BITAES-BC");
            provider.addAlias("Alg.Alias.SecretKeyFactory.PBEWITHSHA-256AND256BITAES-BC", "PBEWITHSHA256AND256BITAES-BC");

            provider.addAlias("AlgorithmParameters", "PBKDF-PKCS12",
                BCObjectIdentifiers.bc_pbe_sha1_pkcs12_aes128_cbc, BCObjectIdentifiers.bc_pbe_sha1_pkcs12_aes192_cbc,
                BCObjectIdentifiers.bc_pbe_sha1_pkcs12_aes256_cbc, BCObjectIdentifiers.bc_pbe_sha256_pkcs12_aes128_cbc,
                BCObjectIdentifiers.bc_pbe_sha256_pkcs12_aes192_cbc, BCObjectIdentifiers.bc_pbe_sha256_pkcs12_aes256_cbc);
        }

        provider.addAlgorithmImplementation("Mac.GMAC", PREFIX + "$AESGMAC", generalAesAttributes, new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseMac(FipsAES.GMAC, new FipsAES.MACOperatorFactory(), new AuthParametersCreator(FipsAES.GMAC));
            }
        });
        provider.addAlias("Mac", "GMAC", "AESGMAC", "AES-GMAC");

        provider.addAlgorithmImplementation("Mac.CMAC", PREFIX + "$AESCMAC", generalAesAttributes, new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseMac(FipsAES.CMAC, new FipsAES.MACOperatorFactory(), new AuthParametersCreator(FipsAES.CMAC));
            }
        });
        provider.addAlias("Mac", "CMAC", "AESCMAC", "AES-CMAC");

        provider.addAlgorithmImplementation("Mac.CCMMAC", PREFIX + "$AESCCMMAC", generalAesAttributes, new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseMac(FipsAES.CCM, new FipsAES.MACOperatorFactory(), new AuthParametersCreator(FipsAES.CCM.withMACSize(128)));
            }
        });
        provider.addAlias("Mac", "CCMMAC", "CCM", "AESCCMMAC", "AES-CCMMAC");

        provider.addAlgorithmImplementation("Mac", NISTObjectIdentifiers.id_aes128_CCM, PREFIX + "$AES128CCMMAC", generalAesAttributes, new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseMac(FipsAES.CCM, new FipsAES.MACOperatorFactory(), new AuthParametersCreator(FipsAES.CCM.withMACSize(128)), 128);
            }
        });
        provider.addAlgorithmImplementation("Mac", NISTObjectIdentifiers.id_aes192_CCM, PREFIX + "$AES192CCMMAC", generalAesAttributes, new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseMac(FipsAES.CCM, new FipsAES.MACOperatorFactory(), new AuthParametersCreator(FipsAES.CCM.withMACSize(128)), 192);
            }
        });
        provider.addAlgorithmImplementation("Mac", NISTObjectIdentifiers.id_aes256_CCM, PREFIX + "$AES256CCMMAC", generalAesAttributes, new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseMac(FipsAES.CCM, new FipsAES.MACOperatorFactory(), new AuthParametersCreator(FipsAES.CCM.withMACSize(128)), 256);
            }
        });
    }

    public static class AlgParamGenGCM
        extends BaseAlgorithmParameterGenerator
    {
        private final String paramsType;

        private int ivLength = 12;

        AlgParamGenGCM(BouncyCastleFipsProvider fipsProvider, String paramsType, int defaultTagSize)
        {
            super(fipsProvider, defaultTagSize);
            this.paramsType = paramsType;
        }

        protected void engineInit(
            AlgorithmParameterSpec genParamSpec,
            SecureRandom random)
            throws InvalidAlgorithmParameterException
        {
            if (!GcmSpecUtil.gcmSpecExists())
            {
                throw new InvalidAlgorithmParameterException("No supported AlgorithmParameterSpec for parameter generation");
            }

            if (GcmSpecUtil.isGcmSpec(genParamSpec))
            {
                try
                {
                    GCMParameters params = GcmSpecUtil.extractGcmParameters(genParamSpec);

                    ivLength = params.getNonce().length;
                    strength = params.getIcvLen() * 8;
                }
                catch (Exception e)
                {
                    throw new InvalidAlgorithmParameterException("Cannot process GCMParameterSpec: " + e.getMessage(), e);
                }
                this.random = random;
            }
            else
            {
                throw new InvalidAlgorithmParameterException("No supported AlgorithmParameterSpec for parameter generation");
            }
        }

        protected AlgorithmParameters engineGenerateParameters()
        {
            byte[] nonce = new byte[ivLength];

            if (CryptoServicesRegistrar.isInApprovedOnlyMode())
            {
                // The FIPS IG A.5 requires use of a FIPS approved DRBG, unfortunately the
                // JCA may create its own DRBG if one is required, In case this happens if
                // we are running in approved mode we override the passed in random and use
                // our local approved one.
                if (!(random instanceof FipsSecureRandom) && !(random.getProvider() instanceof BouncyCastleFipsProvider))
                {
                    fipsProvider.getDefaultSecureRandom().nextBytes(nonce);
                }
                else
                {
                    random.nextBytes(nonce);
                }
            }
            else
            {
                random.nextBytes(nonce);
            }
            AlgorithmParameters params;

            try
            {
                params = AlgorithmParameters.getInstance(paramsType, fipsProvider);
                params.init(new GCMParameters(nonce, strength / 8).getEncoded());
            }
            catch (Exception e)
            {
                throw new IllegalStateException(e.getMessage(), e);
            }

            return params;
        }
    }
}
