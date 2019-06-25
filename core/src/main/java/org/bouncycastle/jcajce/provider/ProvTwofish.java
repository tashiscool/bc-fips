package org.bouncycastle.jcajce.provider;

import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEParameterSpec;

import org.bouncycastle.crypto.AuthenticationParametersWithIV;
import org.bouncycastle.crypto.Parameters;
import org.bouncycastle.crypto.ParametersWithIV;
import org.bouncycastle.crypto.PasswordBasedDeriver;
import org.bouncycastle.crypto.SymmetricKeyGenerator;
import org.bouncycastle.crypto.general.Twofish;
import org.bouncycastle.jcajce.spec.WrapParameterSpec;

class ProvTwofish
    extends SymmetricAlgorithmProvider
{
    ProvTwofish()
    {
    }

    private static final String PREFIX = ProvTwofish.class.getName();

    private ParametersCreatorProvider<Parameters> generalParametersCreatorProvider = new ParametersCreatorProvider<Parameters>()
    {
        public ParametersCreator get(final Parameters parameters)
        {
            if (Utils.isAuthMode(parameters.getAlgorithm()))
            {
                return new AuthParametersCreator((AuthenticationParametersWithIV)parameters);
            }
            else if (parameters.getAlgorithm().equals(Twofish.KW.getAlgorithm()) || parameters.getAlgorithm().equals(Twofish.KWP.getAlgorithm()))
            {
                return new ParametersCreator()
                {

                    public Parameters createParameters(boolean forEncryption, AlgorithmParameterSpec spec, SecureRandom random)
                        throws InvalidAlgorithmParameterException
                    {
                        if (spec instanceof WrapParameterSpec)
                        {
                            return ((Twofish.WrapParameters)parameters).withUsingInverseFunction(((WrapParameterSpec)spec).useInverseFunction());
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
        final Twofish.AEADOperatorFactory aeadOperatorFactory = new Twofish.AEADOperatorFactory();
        final Twofish.KeyWrapOperatorFactory keyWrapOperatorFactory = new Twofish.KeyWrapOperatorFactory();
        final Twofish.OperatorFactory operatorFactory = new Twofish.OperatorFactory();

        final Class[] cipherSpecs = GcmSpecUtil.getCipherSpecClasses();
        final Class[] ivOnlySpec = new Class[]{IvParameterSpec.class};

        provider.addAlgorithmImplementation("Cipher.TWOFISH", PREFIX + "$ECB", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseCipher.Builder(provider, 128,
                    Twofish.ECBwithPKCS7, Twofish.ECB, Twofish.ECBwithISO10126_2, Twofish.ECBwithISO7816_4, Twofish.ECBwithTBC, Twofish.ECBwithX923,
                    Twofish.CBC, Twofish.CBCwithPKCS7, Twofish.CBCwithISO10126_2, Twofish.CBCwithISO7816_4, Twofish.CBCwithTBC, Twofish.CBCwithX923,
                    Twofish.CBCwithCS1, Twofish.CBCwithCS2, Twofish.CBCwithCS3,
                    Twofish.CFB128, Twofish.CFB8,
                    Twofish.OFB, Twofish.OpenPGPCFB,
                    Twofish.CTR, Twofish.GCM, Twofish.CCM, Twofish.OCB, Twofish.EAX)
                    .withGeneralOperators(generalParametersCreatorProvider, operatorFactory, aeadOperatorFactory)
                    .withParameters(cipherSpecs).build();
            }
        }));

        provider.addAlgorithmImplementation("KeyGenerator.TWOFISH", PREFIX + "$KeyGen", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseKeyGenerator(provider, "Twofish", 128, false, new KeyGeneratorCreator()
                {
                    public SymmetricKeyGenerator createInstance(int keySize, SecureRandom random)
                    {
                        return new Twofish.KeyGenerator(keySize, random);
                    }
                });
            }
        }));

        provider.addAlgorithmImplementation("AlgorithmParameters.TWOFISH", PREFIX + "$AlgParams", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new ASN1AlgorithmParameters("Twofish");
            }
        }));

        provider.addAlgorithmImplementation("Cipher.PBEWITHSHAANDTWOFISH-CBC", PREFIX + "$PBESHA256WithTWOFISHCBC", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseCipher.Builder(provider, 128, Twofish.CBCwithPKCS7)
                    .withFixedKeySize(256)
                    .withScheme(PBEScheme.PKCS12)
                    .withGeneralOperators(generalParametersCreatorProvider, operatorFactory, null)
                    .withParameters(new Class[]{PBEParameterSpec.class}).build();
            }
        }));

        provider.addAlgorithmImplementation("Mac.TWOFISHGMAC", PREFIX + "$GMAC", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseMac(Twofish.GMAC, new Twofish.MACOperatorFactory(), new AuthParametersCreator(Twofish.GMAC));
            }
        }));
        provider.addAlias("Mac", "TWOFISHGMAC", "TWOFISH-GMAC");

        provider.addAlgorithmImplementation("Mac.TWOFISHCMAC", PREFIX + "$CMAC", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseMac(Twofish.CMAC, new Twofish.MACOperatorFactory(), new AuthParametersCreator(Twofish.CMAC));
            }
        }));
        provider.addAlias("Mac", "TWOFISHCMAC", "TWOFISH-CMAC");

        provider.addAlgorithmImplementation("Mac.TWOFISHCCMMAC", PREFIX + "$TWOFISHCCMMAC", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseMac(Twofish.CCM, new Twofish.MACOperatorFactory(), new AuthParametersCreator(Twofish.CCM.withMACSize(128)));
            }
        }));
        provider.addAlias("Mac", "TWOFISHCCMMAC", "TWOFISH-CCMMAC");

        provider.addAlgorithmImplementation("Cipher.TWOFISHKW", PREFIX + "$Wrap", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseWrapCipher.Builder(provider, Twofish.KW).withGeneralOperators(generalParametersCreatorProvider, keyWrapOperatorFactory).withParameters(ivOnlySpec).build();
            }
        }));
        provider.addAlias("Cipher", "TWOFISHKW", "TWOFISHWRAP");
        provider.addAlgorithmImplementation("Cipher.TWOFISHKWP", PREFIX + "$WrapWithPad", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseWrapCipher.Builder(provider, Twofish.KWP).withGeneralOperators(generalParametersCreatorProvider, keyWrapOperatorFactory).withParameters(ivOnlySpec).build();
            }
        }));
        provider.addAlias("Cipher", "TWOFISHKWP", "TWOFISHWRAPPAD");

        provider.addAlgorithmImplementation("SecretKeyFactory.TWOFISH", PREFIX + "$TWOFISHKFACT", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseSecretKeyFactory("Twofish", Twofish.ALGORITHM, new BaseSecretKeyFactory.Validator()
                {
                    public byte[] validated(byte[] keyBytes)
                        throws InvalidKeySpecException
                    {
                        int size = keyBytes.length * 8;
                        if (size < 64 || size > 256)
                        {
                            throw new InvalidKeySpecException("Twofish key must be of length 64-256 bits");
                        }

                        return keyBytes;
                    }
                });
            }
        }));

        provider.addAlgorithmImplementation("SecretKeyFactory.PBEWITHSHAAND256BITTWOFISH-BC", PREFIX + "PBE128TWOFISH", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new ProvPKCS12.KeyFactory("Twofish", PasswordBasedDeriver.KeyType.CIPHER, 256);
            }
        }));
        provider.addAlias("SecretKeyFactory", "PBEWITHSHAAND256BITTWOFISH-BC", "PBEWITHSHA1AND256BITTWOFISH-BC", "PBEWITHSHA-1AND256BITTWOFISH-BC");

    }
}
