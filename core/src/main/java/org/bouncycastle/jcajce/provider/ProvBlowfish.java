package org.bouncycastle.jcajce.provider;

import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.crypto.AuthenticationParametersWithIV;
import org.bouncycastle.crypto.Parameters;
import org.bouncycastle.crypto.ParametersWithIV;
import org.bouncycastle.crypto.SymmetricKeyGenerator;
import org.bouncycastle.crypto.general.Blowfish;

class ProvBlowfish
    extends AlgorithmProvider
{
    ProvBlowfish()
    {
    }

    private static final String PREFIX = ProvBlowfish.class.getName();

    private Class[] availableSpecs =
        {
            IvParameterSpec.class,
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

    public void configure(final BouncyCastleFipsProvider provider)
    {

        provider.addAlgorithmImplementation("Cipher.BLOWFISH", PREFIX + "$ECB", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseCipher.Builder(provider, 64,
                    Blowfish.ECBwithPKCS7, Blowfish.ECB, Blowfish.ECBwithISO10126_2, Blowfish.ECBwithISO7816_4, Blowfish.ECBwithTBC, Blowfish.ECBwithX923,
                    Blowfish.CBC, Blowfish.CBCwithPKCS7, Blowfish.CBCwithISO10126_2, Blowfish.CBCwithISO7816_4, Blowfish.CBCwithTBC, Blowfish.CBCwithX923,
                    Blowfish.CBCwithCS1, Blowfish.CBCwithCS2, Blowfish.CBCwithCS3,
                    Blowfish.CFB64, Blowfish.CFB8,
                    Blowfish.OFB, Blowfish.OpenPGPCFB,
                    Blowfish.CTR, Blowfish.EAX)
                    .withGeneralOperators(generalParametersCreatorProvider, new Blowfish.OperatorFactory(), new Blowfish.AEADOperatorFactory())
                    .withParameters(availableSpecs).build();
            }
        }));
        provider.addAlgorithmImplementation("Cipher", MiscObjectIdentifiers.cryptlib_algorithm_blowfish_CBC, PREFIX + "$CBC", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseCipher.Builder(provider, 64, Blowfish.CBCwithPKCS7)
                    .withGeneralOperators(generalParametersCreatorProvider, new Blowfish.OperatorFactory(), null)
                    .withParameters(availableSpecs).build();
            }
        }));
        provider.addAlgorithmImplementation("KeyGenerator.BLOWFISH", PREFIX + "$KeyGen", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseKeyGenerator(provider, "Blowfish", 128, new KeyGeneratorCreator()
                {
                    public SymmetricKeyGenerator createInstance(int keySize, SecureRandom random)
                    {
                        return new Blowfish.KeyGenerator(keySize, random);
                    }
                });
            }
        }));
        provider.addAlias("KeyGenerator", "BLOWFISH", MiscObjectIdentifiers.cryptlib_algorithm_blowfish_CBC);

        provider.addAlgorithmImplementation("Mac.BLOWFISHCMAC", PREFIX + "$CMAC", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseMac(Blowfish.CMAC, new Blowfish.MACOperatorFactory(), new AuthParametersCreator(Blowfish.CMAC));
            }
        }));
        provider.addAlias("Mac", "BLOWFISHCMAC", "BLOWFISH-CMAC");

        provider.addAlgorithmImplementation("SecretKeyFactory.BLOWFISH", PREFIX + "$BLOWFISHKFACT", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseSecretKeyFactory("Blowfish", Blowfish.ALGORITHM, new BaseSecretKeyFactory.Validator()
                {
                    public byte[] validated(byte[] keyBytes)
                        throws InvalidKeySpecException
                    {
                        int keyLength = keyBytes.length * 8;
                        if (keyLength < 32 || keyLength > 448)
                        {
                            throw new InvalidKeySpecException("Blowfish key must be between 32 and 448 bits inclusive");
                        }

                        return keyBytes;
                    }
                });
            }
        }));

        provider.addAlgorithmImplementation("AlgorithmParameters.BLOWFISH", PREFIX + "$AlgParams", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new ASN1AlgorithmParameters("Blowfish");
            }
        }));
        provider.addAlias("AlgorithmParameters", "BLOWFISH", MiscObjectIdentifiers.cryptlib_algorithm_blowfish_CBC);

        provider.addAlgorithmImplementation("AlgorithmParameterGenerator", MiscObjectIdentifiers.cryptlib_algorithm_blowfish_CBC, PREFIX + "$AlgParamGen", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new IVAlgorithmParameterGenerator(provider, "Blowfish", 8);
            }
        }));
    }
}
