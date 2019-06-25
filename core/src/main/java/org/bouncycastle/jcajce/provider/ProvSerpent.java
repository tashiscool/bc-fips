package org.bouncycastle.jcajce.provider;

import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.asn1.gnu.GNUObjectIdentifiers;
import org.bouncycastle.crypto.AuthenticationParametersWithIV;
import org.bouncycastle.crypto.Parameters;
import org.bouncycastle.crypto.ParametersWithIV;
import org.bouncycastle.crypto.SymmetricKeyGenerator;
import org.bouncycastle.crypto.general.Serpent;
import org.bouncycastle.jcajce.spec.WrapParameterSpec;

class ProvSerpent
    extends SymmetricAlgorithmProvider
{
    ProvSerpent()
    {
    }

    private static final String PREFIX = ProvSerpent.class.getName();

    private ParametersCreatorProvider<Parameters> generalParametersCreatorProvider = new ParametersCreatorProvider<Parameters>()
    {
        public ParametersCreator get(final Parameters parameters)
        {
            if (Utils.isAuthMode(parameters.getAlgorithm()))
            {
                return new AuthParametersCreator((AuthenticationParametersWithIV)parameters);
            }
            else if (parameters.getAlgorithm().equals(Serpent.KW.getAlgorithm()) || parameters.getAlgorithm().equals(Serpent.KWP.getAlgorithm()))
            {
                return new ParametersCreator()
                {

                    public Parameters createParameters(boolean forEncryption, AlgorithmParameterSpec spec, SecureRandom random)
                        throws InvalidAlgorithmParameterException
                    {
                        if (spec instanceof WrapParameterSpec)
                        {
                            return ((Serpent.WrapParameters)parameters).withUsingInverseFunction(((WrapParameterSpec)spec).useInverseFunction());
                        }

                        return parameters;
                    }
                };
            }
            return new IvParametersCreator((ParametersWithIV)parameters);
        }
    };

    public void configure(final BouncyCastleFipsProvider provider)
    {
        final Serpent.OperatorFactory operatorFactory = new Serpent.OperatorFactory();
        final Serpent.AEADOperatorFactory aeadOperatorFactory = new Serpent.AEADOperatorFactory();
        final Serpent.KeyWrapOperatorFactory keyWrapOperatorFactory= new Serpent.KeyWrapOperatorFactory();

        final Class[] cipherSpecs = GcmSpecUtil.getCipherSpecClasses();
        final Class[] ivOnlySpec = new Class[]{IvParameterSpec.class};

        provider.addAlgorithmImplementation("Cipher.SERPENT", PREFIX + "$ECB", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseCipher.Builder(provider, 128,
                    Serpent.ECBwithPKCS7, Serpent.ECB, Serpent.ECBwithISO10126_2, Serpent.ECBwithISO7816_4, Serpent.ECBwithTBC, Serpent.ECBwithX923,
                    Serpent.CBC, Serpent.CBCwithPKCS7, Serpent.CBCwithISO10126_2, Serpent.CBCwithISO7816_4, Serpent.CBCwithTBC, Serpent.CBCwithX923,
                    Serpent.CBCwithCS1, Serpent.CBCwithCS2, Serpent.CBCwithCS3,
                    Serpent.CFB128, Serpent.CFB8,
                    Serpent.OFB,
                    Serpent.CTR, Serpent.GCM, Serpent.CCM, Serpent.OCB, Serpent.EAX)
                    .withGeneralOperators(generalParametersCreatorProvider, operatorFactory, aeadOperatorFactory)
                    .withParameters(cipherSpecs).build();
            }
        }));

        provider.addAlgorithmImplementation("KeyGenerator.SERPENT", PREFIX + "$KeyGen", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseKeyGenerator(provider, "Serpent", 128, false, new KeyGeneratorCreator()
                {
                    public SymmetricKeyGenerator createInstance(int keySize, SecureRandom random)
                    {
                        return new Serpent.KeyGenerator(keySize, random);
                    }
                });
            }
        }));
        provider.addAlias("KeyGenerator", "SERPENT", GNUObjectIdentifiers.Serpent);

        EngineCreator serpent128KeyGenCreator = new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseKeyGenerator(provider, "Serpent", 128, true, new KeyGeneratorCreator()
                {
                    public SymmetricKeyGenerator createInstance(int keySize, SecureRandom random)
                    {
                        return new Serpent.KeyGenerator(128, random);
                    }
                });
            }
        });

        addKeyGeneratorForOIDs(provider, PREFIX, serpent128KeyGenCreator,
            GNUObjectIdentifiers.Serpent_128_CBC, GNUObjectIdentifiers.Serpent_128_CFB, GNUObjectIdentifiers.Serpent_128_ECB, GNUObjectIdentifiers.Serpent_128_OFB);

        EngineCreator serpent192KeyGenCreator = new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseKeyGenerator(provider, "Serpent", 192, true, new KeyGeneratorCreator()
                {
                    public SymmetricKeyGenerator createInstance(int keySize, SecureRandom random)
                    {
                        return new Serpent.KeyGenerator(192, random);
                    }
                });
            }
        });
        addKeyGeneratorForOIDs(provider, PREFIX, serpent192KeyGenCreator,
            GNUObjectIdentifiers.Serpent_192_CBC, GNUObjectIdentifiers.Serpent_192_CFB, GNUObjectIdentifiers.Serpent_192_ECB, GNUObjectIdentifiers.Serpent_192_OFB);

        EngineCreator serpent256KeyGenCreator = new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseKeyGenerator(provider, "Serpent", 256, true, new KeyGeneratorCreator()
                {
                    public SymmetricKeyGenerator createInstance(int keySize, SecureRandom random)
                    {
                        return new Serpent.KeyGenerator(256, random);
                    }
                });
            }
        });
        addKeyGeneratorForOIDs(provider, PREFIX, serpent256KeyGenCreator,
            GNUObjectIdentifiers.Serpent_256_CBC, GNUObjectIdentifiers.Serpent_256_CFB, GNUObjectIdentifiers.Serpent_256_ECB, GNUObjectIdentifiers.Serpent_256_OFB);

        provider.addAlgorithmImplementation("AlgorithmParameters.SERPENT", PREFIX + "$AlgParams", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new ASN1AlgorithmParameters("Serpent");
            }
        }));
        provider.addAlias("AlgorithmParameters", "SERPENT",
            GNUObjectIdentifiers.Serpent_128_CBC, GNUObjectIdentifiers.Serpent_192_CBC, GNUObjectIdentifiers.Serpent_256_CBC,
            GNUObjectIdentifiers.Serpent_128_CFB, GNUObjectIdentifiers.Serpent_192_CFB, GNUObjectIdentifiers.Serpent_256_CFB,
            GNUObjectIdentifiers.Serpent_128_OFB, GNUObjectIdentifiers.Serpent_192_OFB, GNUObjectIdentifiers.Serpent_256_OFB);

        provider.addAlgorithmImplementation("AlgorithmParameterGenerator", GNUObjectIdentifiers.Serpent_128_CBC, PREFIX + "$AlgParamGen", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new IVAlgorithmParameterGenerator(provider, "Serpent", 16);
            }
        }));
        provider.addAlias("AlgorithmParameterGenerator", GNUObjectIdentifiers.Serpent_128_CBC.getId(),
            GNUObjectIdentifiers.Serpent_192_CBC, GNUObjectIdentifiers.Serpent_256_CBC,
            GNUObjectIdentifiers.Serpent_128_CFB, GNUObjectIdentifiers.Serpent_192_CFB, GNUObjectIdentifiers.Serpent_256_CFB,
            GNUObjectIdentifiers.Serpent_128_OFB, GNUObjectIdentifiers.Serpent_192_OFB, GNUObjectIdentifiers.Serpent_256_OFB);

        provider.addAlgorithmImplementation("Mac.SERPENTGMAC", PREFIX + "$GMAC", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseMac(Serpent.GMAC, new Serpent.MACOperatorFactory(), new AuthParametersCreator(Serpent.GMAC));
            }
        }));
        provider.addAlias("Mac", "SERPENTGMAC", "SERPENT-GMAC");

        provider.addAlgorithmImplementation("Mac.SERPENTCMAC", PREFIX + "$CMAC", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseMac(Serpent.CMAC, new Serpent.MACOperatorFactory(), new AuthParametersCreator(Serpent.CMAC));
            }
        }));
        provider.addAlias("Mac", "SERPENTCMAC", "SERPENT-CMAC");

        provider.addAlgorithmImplementation("Mac.SERPENTCCMMAC", PREFIX + "$SERPENTCCMMAC", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseMac(Serpent.CCM, new Serpent.MACOperatorFactory(), new AuthParametersCreator(Serpent.CCM.withMACSize(128)));
            }
        }));
        provider.addAlias("Mac", "SERPENTCCMMAC", "SERPENT-CCMMAC");

        provider.addAlgorithmImplementation("Cipher.SERPENTKW", PREFIX + "$Wrap", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseWrapCipher.Builder(provider, Serpent.KW).withGeneralOperators(generalParametersCreatorProvider, keyWrapOperatorFactory).withParameters(ivOnlySpec).build();
            }
        }));
        provider.addAlias("Cipher", "SERPENTKW", "SERPENTWRAP");
        provider.addAlgorithmImplementation("Cipher.SERPENTKWP", PREFIX + "$WrapWithPad", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseWrapCipher.Builder(provider, Serpent.KWP).withGeneralOperators(generalParametersCreatorProvider, keyWrapOperatorFactory).withParameters(ivOnlySpec).build();
            }
        }));
        provider.addAlias("Cipher", "SERPENTKWP", "SERPENTWRAPPAD");

        provider.addAlgorithmImplementation("SecretKeyFactory.SERPENT", PREFIX + "$SERPENTKFACT", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseSecretKeyFactory("Serpent", Serpent.ALGORITHM, new BaseSecretKeyFactory.Validator()
                {
                    public byte[] validated(byte[] keyBytes)
                        throws InvalidKeySpecException
                    {
                        int size = keyBytes.length * 8;
                        if (size < 32 || size % 32 != 0 || size > 256)
                        {
                            throw new InvalidKeySpecException("Serpent key must be a multiple of 32 bits");
                        }

                        return keyBytes;
                    }
                });
            }
        }));

        provider.addAlgorithmImplementation("Cipher", GNUObjectIdentifiers.Serpent_128_ECB, PREFIX + "ECB128", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseCipher.Builder(provider, 128, Serpent.ECBwithPKCS7)
                    .withGeneralOperators(generalParametersCreatorProvider, operatorFactory, null)
                    .withFixedKeySize(128).build();
            }
        }));

        provider.addAlgorithmImplementation("Cipher", GNUObjectIdentifiers.Serpent_192_ECB, PREFIX + "ECB192", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseCipher.Builder(provider, 128, Serpent.ECBwithPKCS7)
                    .withGeneralOperators(generalParametersCreatorProvider, operatorFactory, null)
                    .withFixedKeySize(192).build();
            }
        }));

        provider.addAlgorithmImplementation("Cipher", GNUObjectIdentifiers.Serpent_256_ECB, PREFIX + "ECB256", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseCipher.Builder(provider, 128, Serpent.ECBwithPKCS7)
                    .withGeneralOperators(generalParametersCreatorProvider, operatorFactory, null)
                    .withFixedKeySize(256).build();
            }
        }));

        provider.addAlgorithmImplementation("Cipher", GNUObjectIdentifiers.Serpent_128_CBC, PREFIX + "CBC128", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseCipher.Builder(provider, 128, Serpent.CBCwithPKCS7)
                    .withParameters(ivOnlySpec)
                    .withGeneralOperators(generalParametersCreatorProvider, operatorFactory, null)
                    .withFixedKeySize(128).build();
            }
        }));

        provider.addAlgorithmImplementation("Cipher", GNUObjectIdentifiers.Serpent_192_CBC, PREFIX + "CBC192", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseCipher.Builder(provider, 128, Serpent.CBCwithPKCS7)
                    .withParameters(ivOnlySpec)
                    .withGeneralOperators(generalParametersCreatorProvider, operatorFactory, null)
                    .withFixedKeySize(192).build();
            }
        }));

        provider.addAlgorithmImplementation("Cipher", GNUObjectIdentifiers.Serpent_256_CBC, PREFIX + "CBC256", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseCipher.Builder(provider, 128, Serpent.CBCwithPKCS7)
                    .withParameters(ivOnlySpec)
                    .withGeneralOperators(generalParametersCreatorProvider, operatorFactory, null)
                    .withFixedKeySize(256).build();
            }
        }));

        provider.addAlgorithmImplementation("Cipher", GNUObjectIdentifiers.Serpent_128_CFB, PREFIX + "CFB128", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseCipher.Builder(provider, 128, Serpent.CFB128)
                    .withParameters(ivOnlySpec)
                    .withGeneralOperators(generalParametersCreatorProvider, operatorFactory, null)
                    .withFixedKeySize(128).build();
            }
        }));

        provider.addAlgorithmImplementation("Cipher", GNUObjectIdentifiers.Serpent_192_CFB, PREFIX + "CFB192", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseCipher.Builder(provider, 128, Serpent.CFB128)
                    .withParameters(ivOnlySpec)
                    .withGeneralOperators(generalParametersCreatorProvider, operatorFactory, null)
                    .withFixedKeySize(192).build();
            }
        }));

        provider.addAlgorithmImplementation("Cipher", GNUObjectIdentifiers.Serpent_256_CFB, PREFIX + "CFB256", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseCipher.Builder(provider, 128, Serpent.CFB128)
                    .withParameters(ivOnlySpec)
                    .withGeneralOperators(generalParametersCreatorProvider, operatorFactory, null)
                    .withFixedKeySize(256).build();
            }
        }));

        provider.addAlgorithmImplementation("Cipher", GNUObjectIdentifiers.Serpent_128_OFB, PREFIX + "OFB128", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseCipher.Builder(provider, 128, Serpent.OFB)
                    .withParameters(ivOnlySpec)
                    .withGeneralOperators(generalParametersCreatorProvider, operatorFactory, null)
                    .withFixedKeySize(128).build();
            }
        }));

        provider.addAlgorithmImplementation("Cipher", GNUObjectIdentifiers.Serpent_192_OFB, PREFIX + "OFB192", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseCipher.Builder(provider, 128, Serpent.OFB)
                    .withParameters(ivOnlySpec)
                    .withGeneralOperators(generalParametersCreatorProvider, operatorFactory, null)
                    .withFixedKeySize(192).build();
            }
        }));

        provider.addAlgorithmImplementation("Cipher", GNUObjectIdentifiers.Serpent_256_OFB, PREFIX + "OFB256", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseCipher.Builder(provider, 128, Serpent.OFB)
                    .withParameters(ivOnlySpec)
                    .withGeneralOperators(generalParametersCreatorProvider, operatorFactory, null)
                    .withFixedKeySize(256).build();
            }
        }));
    }
}
