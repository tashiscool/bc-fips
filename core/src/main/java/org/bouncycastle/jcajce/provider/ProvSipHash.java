package org.bouncycastle.jcajce.provider;

import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;

import org.bouncycastle.crypto.AuthenticationParameters;
import org.bouncycastle.crypto.SymmetricKeyGenerator;
import org.bouncycastle.crypto.general.SipHash;

final class ProvSipHash
    extends AlgorithmProvider
{
    private static final String PREFIX = ProvSipHash.class.getName();

    public void configure(final BouncyCastleFipsProvider provider)
    {
        provider.addAlgorithmImplementation("Mac.SIPHASH-2-4", PREFIX + "$Mac24", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseMac(SipHash.SIPHASH_2_4, new SipHash.MACOperatorFactory(), new MacParametersCreator()
                {
                    public AuthenticationParameters getBaseParameters()
                    {
                        return new SipHash.AuthParameters(SipHash.SIPHASH_2_4);
                    }

                    public AuthenticationParameters createParameters(boolean forEncryption, AlgorithmParameterSpec spec, SecureRandom random)
                        throws InvalidAlgorithmParameterException
                    {
                        return new SipHash.AuthParameters(SipHash.SIPHASH_2_4);
                    }
                });
            }
        }));
        provider.addAlias("Alg.Alias.Mac.SIPHASH", "SIPHASH-2-4");
        provider.addAlgorithmImplementation("Mac.SIPHASH-4-8", PREFIX + "$Mac48", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseMac(SipHash.SIPHASH_4_8, new SipHash.MACOperatorFactory(), new MacParametersCreator()
                {
                    public AuthenticationParameters getBaseParameters()
                    {
                        return new SipHash.AuthParameters(SipHash.SIPHASH_4_8);
                    }

                    public AuthenticationParameters createParameters(boolean forEncryption, AlgorithmParameterSpec spec, SecureRandom random)
                        throws InvalidAlgorithmParameterException
                    {
                        return new SipHash.AuthParameters(SipHash.SIPHASH_4_8);
                    }
                });
            }
        }));

        provider.addAlgorithmImplementation("SecretKeyFactory.SIPHASH", PREFIX + "$SIPHASHKFACT", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseSecretKeyFactory("SipHash", SipHash.ALGORITHM, new BaseSecretKeyFactory.Validator()
                {
                    public byte[] validated(byte[] keyBytes)
                        throws InvalidKeySpecException
                    {
                        int size = keyBytes.length * 8;
                        if (size != 128)
                        {
                            throw new InvalidKeySpecException("SipHash key must be of length 128 bits");
                        }

                        return keyBytes;
                    }
                });
            }
        }));
        provider.addAlias("SecretKeyFactory", "SIPHASH", "SIPHASH-2-4", "SIPHASH-4-8");

        provider.addAlgorithmImplementation("KeyGenerator.SIPHASH", PREFIX + "$KeyGen", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseKeyGenerator(provider, "SipHash", 128, true, new KeyGeneratorCreator()
                {
                    public SymmetricKeyGenerator createInstance(int keySize, SecureRandom random)
                    {
                        return new SipHash.KeyGenerator(SipHash.ALGORITHM, random);
                    }
                });
            }
        }));
        provider.addAlias("KeyGenerator", "SIPHASH", "SIPHASH-2-4", "SIPHASH-4-8");
    }
}
