package org.bouncycastle.jcajce.provider;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.asn1.ntt.NTTObjectIdentifiers;
import org.bouncycastle.crypto.AuthenticationParametersWithIV;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.Parameters;
import org.bouncycastle.crypto.ParametersWithIV;
import org.bouncycastle.crypto.SymmetricKeyGenerator;
import org.bouncycastle.crypto.general.Camellia;
import org.bouncycastle.jcajce.spec.WrapParameterSpec;

class ProvCamellia
    extends SymmetricAlgorithmProvider
{
    private Camellia.OperatorFactory operatorFactory;
    private Camellia.AEADOperatorFactory aeadOperatorFactory;
    private Camellia.KeyWrapOperatorFactory keyWrapOperatorFactory;

    ProvCamellia()
    {

        if (!CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            aeadOperatorFactory = new Camellia.AEADOperatorFactory();
            keyWrapOperatorFactory = new Camellia.KeyWrapOperatorFactory();
            operatorFactory = new Camellia.OperatorFactory();
        }
    }

    private static final String PREFIX = ProvCamellia.class.getName();

    private ParametersCreatorProvider<Parameters> generalParametersCreatorProvider = new ParametersCreatorProvider<Parameters>()
    {
        public ParametersCreator get(final Parameters parameters)
        {
            if (Utils.isAuthMode(parameters.getAlgorithm()))
            {
                return new AuthParametersCreator((AuthenticationParametersWithIV)parameters);
            }
            else if (parameters.getAlgorithm().equals(Camellia.KW.getAlgorithm()) || parameters.getAlgorithm().equals(Camellia.KWP.getAlgorithm()))
            {
                return new ParametersCreator()
                {

                    public Parameters createParameters(boolean forEncryption, AlgorithmParameterSpec spec, SecureRandom random)
                        throws InvalidAlgorithmParameterException
                    {
                        if (spec instanceof WrapParameterSpec)
                        {
                            return ((Camellia.WrapParameters)parameters).withUsingInverseFunction(((WrapParameterSpec)spec).useInverseFunction());
                        }

                        return parameters;
                    }
                };
            }
            return new IvParametersCreator((ParametersWithIV)parameters);
        }
    };

    private Camellia.OperatorFactory getGeneralOperatorFactory()
    {
        if (CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            return null;
        }

        return operatorFactory;
    }

    public void configure(final BouncyCastleFipsProvider provider)
    {
        final Class[] cipherSpecs = GcmSpecUtil.getCipherSpecClasses();
        final Class[] ivOnlySpec = new Class[]{IvParameterSpec.class};

        provider.addAlgorithmImplementation("AlgorithmParameters.CAMELLIA", PREFIX + "$AlgParams", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new ASN1AlgorithmParameters("Camellia");
            }
        }));
        provider.addAlias("AlgorithmParameters", "CAMELLIA", NTTObjectIdentifiers.id_camellia128_cbc, NTTObjectIdentifiers.id_camellia192_cbc, NTTObjectIdentifiers.id_camellia256_cbc);

        provider.addAlgorithmImplementation("AlgorithmParameterGenerator", NTTObjectIdentifiers.id_camellia128_cbc, PREFIX + "$AlgParamGen", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new IVAlgorithmParameterGenerator(provider, "Camellia", 16);
            }
        }));
        provider.addAlias("AlgorithmParameterGenerator", NTTObjectIdentifiers.id_camellia128_cbc.getId(), NTTObjectIdentifiers.id_camellia192_cbc, NTTObjectIdentifiers.id_camellia256_cbc);

        provider.addAlgorithmImplementation("SecretKeyFactory.CAMELLIA", PREFIX + "$CAMELLIAKFACT", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseSecretKeyFactory("Camellia", Camellia.ALGORITHM, new BaseSecretKeyFactory.Validator()
                {
                    public byte[] validated(byte[] keyBytes)
                        throws InvalidKeySpecException
                    {
                        int size = keyBytes.length * 8;
                        if (size != 128 && size != 192 && size != 256)
                        {
                            throw new InvalidKeySpecException("Provided key data wrong size for Camellia");
                        }

                        return keyBytes;
                    }
                });
            }
        }));

        provider.addAlgorithmImplementation("Cipher.CAMELLIA", PREFIX + "$ECB", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseCipher.Builder(provider, 128,
                    Camellia.ECBwithPKCS7, Camellia.ECB, Camellia.ECBwithISO10126_2, Camellia.ECBwithISO7816_4, Camellia.ECBwithTBC, Camellia.ECBwithX923,
                    Camellia.CBC, Camellia.CBCwithPKCS7, Camellia.CBCwithISO10126_2, Camellia.CBCwithISO7816_4, Camellia.CBCwithTBC, Camellia.CBCwithX923,
                    Camellia.CBCwithCS1, Camellia.CBCwithCS2, Camellia.CBCwithCS3,
                    Camellia.CFB128, Camellia.CFB8, Camellia.OpenPGPCFB,
                    Camellia.OFB,
                    Camellia.CTR, Camellia.GCM, Camellia.CCM, Camellia.OCB, Camellia.EAX)
                    .withGeneralOperators(generalParametersCreatorProvider, getGeneralOperatorFactory(), aeadOperatorFactory)
                    .withParameters(cipherSpecs).build();
            }
        }));

        provider.addAlgorithmImplementation("Cipher", NTTObjectIdentifiers.id_camellia128_cbc, PREFIX + "$CBC128",
            new GuardedEngineCreator(new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new BaseCipher.Builder(provider, 128, Camellia.CBCwithPKCS7)
                        .withParameters(ivOnlySpec)
                        .withGeneralOperators(generalParametersCreatorProvider, operatorFactory, null)
                        .withFixedKeySize(128)
                        .build();
                }
            })
        );

        provider.addAlgorithmImplementation("Cipher", NTTObjectIdentifiers.id_camellia192_cbc, PREFIX + "$CBC192",
            new GuardedEngineCreator(new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new BaseCipher.Builder(provider, 128, Camellia.CBCwithPKCS7)
                        .withParameters(ivOnlySpec)
                        .withGeneralOperators(generalParametersCreatorProvider, operatorFactory, null)
                        .withFixedKeySize(192)
                        .build();
                }
            })
        );

        provider.addAlgorithmImplementation("Cipher", NTTObjectIdentifiers.id_camellia256_cbc, PREFIX + "$CBC256",
            new GuardedEngineCreator(new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new BaseCipher.Builder(provider, 128, Camellia.CBCwithPKCS7)
                        .withParameters(ivOnlySpec)
                        .withGeneralOperators(generalParametersCreatorProvider, operatorFactory, null)
                        .withFixedKeySize(256)
                        .build();
                }
            })
        );


        provider.addAlgorithmImplementation("Cipher.CAMELLIAKW", PREFIX + "$Wrap", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseWrapCipher.Builder(provider, Camellia.KW).withGeneralOperators(generalParametersCreatorProvider, keyWrapOperatorFactory).withParameters(ivOnlySpec).build();
            }
        }));
        provider.addAlgorithmImplementation("Cipher", NTTObjectIdentifiers.id_camellia128_wrap, PREFIX + "$Wrap128", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
                throws NoSuchAlgorithmException
            {
                return new BaseWrapCipher.Builder(provider, Camellia.KW).withFixedKeySize(128).withGeneralOperators(generalParametersCreatorProvider, keyWrapOperatorFactory).withParameters(ivOnlySpec).build();
            }
        }));
        provider.addAlgorithmImplementation("Cipher", NTTObjectIdentifiers.id_camellia192_wrap, PREFIX + "$Wrap192", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
                throws NoSuchAlgorithmException
            {
                return new BaseWrapCipher.Builder(provider, Camellia.KW).withFixedKeySize(192).withGeneralOperators(generalParametersCreatorProvider, keyWrapOperatorFactory).withParameters(ivOnlySpec).build();
            }
        }));
        provider.addAlgorithmImplementation("Cipher", NTTObjectIdentifiers.id_camellia256_wrap, PREFIX + "$Wrap256", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
                throws NoSuchAlgorithmException
            {
                return new BaseWrapCipher.Builder(provider, Camellia.KW).withFixedKeySize(256).withGeneralOperators(generalParametersCreatorProvider, keyWrapOperatorFactory).withParameters(ivOnlySpec).build();
            }
        }));
        provider.addAlias("Cipher", "CAMELLIAKW", "CAMELLIAWRAP");

        provider.addAlgorithmImplementation("Cipher.CAMELLIAKWP", PREFIX + "$WrapWithPad", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseWrapCipher.Builder(provider, Camellia.KWP).withGeneralOperators(generalParametersCreatorProvider, keyWrapOperatorFactory).withParameters(ivOnlySpec).build();
            }
        }));
        provider.addAlias("Cipher", "CAMELLIAKWP", "CAMELLIAWRAPPAD");

        provider.addAlgorithmImplementation("KeyGenerator.CAMELLIA", PREFIX + "$KeyGen", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseKeyGenerator(provider, "Camellia", 128, false, new KeyGeneratorCreator()
                {
                    public SymmetricKeyGenerator createInstance(int keySize, SecureRandom random)
                    {
                        return new Camellia.KeyGenerator(keySize, random);
                    }
                });
            }
        }));

        GuardedEngineCreator camellia128Gen = new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseKeyGenerator(provider, "Camellia", 128, true, new KeyGeneratorCreator()
                {
                    public SymmetricKeyGenerator createInstance(int keySize, SecureRandom random)
                    {
                        return new Camellia.KeyGenerator(128, random);
                    }
                });
            }
        });
        addKeyGeneratorForOIDs(provider, PREFIX, camellia128Gen, NTTObjectIdentifiers.id_camellia128_cbc, NTTObjectIdentifiers.id_camellia128_wrap);

        GuardedEngineCreator camellia192Gen = new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseKeyGenerator(provider, "Camellia", 192, true, new KeyGeneratorCreator()
                {
                    public SymmetricKeyGenerator createInstance(int keySize, SecureRandom random)
                    {
                        return new Camellia.KeyGenerator(192, random);
                    }
                });
            }
        });
        addKeyGeneratorForOIDs(provider, PREFIX, camellia192Gen, NTTObjectIdentifiers.id_camellia192_cbc, NTTObjectIdentifiers.id_camellia192_wrap);

        GuardedEngineCreator camellia256Gen = new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseKeyGenerator(provider, "Camellia", 256, true, new KeyGeneratorCreator()
                {
                    public SymmetricKeyGenerator createInstance(int keySize, SecureRandom random)
                    {
                        return new Camellia.KeyGenerator(256, random);
                    }
                });
            }
        });
        addKeyGeneratorForOIDs(provider, PREFIX, camellia256Gen, NTTObjectIdentifiers.id_camellia256_cbc, NTTObjectIdentifiers.id_camellia256_wrap);

        provider.addAlgorithmImplementation("Mac.CAMELLIAGMAC", PREFIX + "$GMAC", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseMac(Camellia.GMAC, new Camellia.MACOperatorFactory(), new AuthParametersCreator(Camellia.GMAC));
            }
        }));
        provider.addAlias("Mac", "CAMELLIAGMAC", "CAMELLIA-GMAC");

        provider.addAlgorithmImplementation("Mac.CAMELLIACMAC", PREFIX + "$CMAC", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseMac(Camellia.CMAC, new Camellia.MACOperatorFactory(), new AuthParametersCreator(Camellia.CMAC));
            }
        }));
        provider.addAlias("Mac", "CAMELLIACMAC", "CAMELLIA-CMAC");

        provider.addAlgorithmImplementation("Mac.CAMELLIACCMMAC", PREFIX + "$CAEMLLIACCMMAC", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseMac(Camellia.CCM, new Camellia.MACOperatorFactory(), new AuthParametersCreator(Camellia.CCM.withMACSize(128)));
            }
        }));
        provider.addAlias("Mac", "CAMELLIACCMMAC", "CAMELLIA-CCMMAC");
    }
}
