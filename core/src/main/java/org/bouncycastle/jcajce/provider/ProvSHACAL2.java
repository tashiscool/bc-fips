package org.bouncycastle.jcajce.provider;

import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

import org.bouncycastle.crypto.AuthenticationParametersWithIV;
import org.bouncycastle.crypto.Parameters;
import org.bouncycastle.crypto.ParametersWithIV;
import org.bouncycastle.crypto.SymmetricKeyGenerator;
import org.bouncycastle.crypto.general.SHACAL2;

class ProvSHACAL2
    extends SymmetricAlgorithmProvider
{
    private static final String PREFIX = ProvSHACAL2.class.getName();

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

    public void configure(final BouncyCastleFipsProvider provider)
    {
        final Class[] cipherSpecs = GcmSpecUtil.getCipherSpecClasses();
        final SHACAL2.OperatorFactory operatorFactory = new SHACAL2.OperatorFactory();
        final SHACAL2.AEADOperatorFactory aeadOperatorFactory = new SHACAL2.AEADOperatorFactory();

        provider.addAlgorithmImplementation("Cipher.SHACAL-2", PREFIX + "$ECB", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseCipher.Builder(provider, 256,
                    SHACAL2.ECBwithPKCS7, SHACAL2.ECB, SHACAL2.ECBwithISO10126_2, SHACAL2.ECBwithISO7816_4, SHACAL2.ECBwithTBC, SHACAL2.ECBwithX923,
                    SHACAL2.CBC, SHACAL2.CBCwithPKCS7, SHACAL2.CBCwithISO10126_2, SHACAL2.CBCwithISO7816_4, SHACAL2.CBCwithTBC, SHACAL2.CBCwithX923,
                    SHACAL2.CBCwithCS1, SHACAL2.CBCwithCS2, SHACAL2.CBCwithCS3,
                    SHACAL2.CFB256, SHACAL2.CFB8,
                    SHACAL2.OFB,
                    SHACAL2.CTR, SHACAL2.EAX)
                    .withGeneralOperators(generalParametersCreatorProvider, operatorFactory, aeadOperatorFactory)
                    .withParameters(cipherSpecs).build();
            }
        }));
        provider.addAlias("Cipher", "SHACAL-2", "SHACAL2");

        provider.addAlgorithmImplementation("KeyGenerator.SHACAL-2", PREFIX + "$KeyGen", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseKeyGenerator(provider, "SHACAL-2", 128, false, new KeyGeneratorCreator()
                {
                    public SymmetricKeyGenerator createInstance(int keySize, SecureRandom random)
                    {
                        return new SHACAL2.KeyGenerator(keySize, random);
                    }
                });
            }
        }));
        provider.addAlias("KeyGenerator", "SHACAL-2", "SHACAL2");

        provider.addAlgorithmImplementation("AlgorithmParameters.SHACAL-2", PREFIX + "$AlgParams", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new ASN1AlgorithmParameters("SHACAL-2");
            }
        }));
        provider.addAlias("AlgorithmParameters", "SHACAL-2", "SHACAL2");

        provider.addAlgorithmImplementation("Mac.SHACAL-2CMAC", PREFIX + "$CMAC", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseMac(SHACAL2.CMAC, new SHACAL2.MACOperatorFactory(), new AuthParametersCreator(SHACAL2.CMAC));
            }
        }));
        provider.addAlias("Mac", "SHACAL-2CMAC", "SHACAL-2-CMAC");

        provider.addAlgorithmImplementation("SecretKeyFactory.SHACAL-2", PREFIX + "$SHACAL2KFACT", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseSecretKeyFactory("SHACAL-2", SHACAL2.ALGORITHM, new BaseSecretKeyFactory.Validator()
                {
                    public byte[] validated(byte[] keyBytes)
                        throws InvalidKeySpecException
                    {
                        int size = keyBytes.length * 8;
                        if (size == 0 || size > 512 || size < 128 || size % 64 != 0)
                        {
                            throw new InvalidKeySpecException("SHACAL-2 key must be 128 - 512 bits and a multiple of 64");
                        }

                        return keyBytes;
                    }
                });
            }
        }));
        provider.addAlias("SecretKeyFactory", "SHACAL-2", "SHACAL2");
    }
}
