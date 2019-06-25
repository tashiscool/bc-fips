package org.bouncycastle.jcajce.provider;

import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.spec.PBEParameterSpec;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.crypto.Parameters;
import org.bouncycastle.crypto.PasswordBasedDeriver;
import org.bouncycastle.crypto.SymmetricKeyGenerator;
import org.bouncycastle.crypto.general.ARC4;

final class ProvARC4
    extends AlgorithmProvider
{
    private static final String PREFIX = ProvARC4.class.getName();

    private ParametersCreator parametersCreator = new ParametersCreator()
    {

        public Parameters createParameters(boolean forEncryption, AlgorithmParameterSpec spec, SecureRandom random)
        {
            return ARC4.STREAM;
        }
    };

    private ParametersCreatorProvider<Parameters> generalParametersCreatorProvider = new ParametersCreatorProvider<Parameters>()
    {
        public ParametersCreator get(Parameters parameters)
        {
            return parametersCreator;
        }
    };

    public void configure(final BouncyCastleFipsProvider provider)
    {
        provider.addAlgorithmImplementation("Cipher.ARC4", PREFIX + "$Base", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseCipher.Builder(provider, 0, ARC4.STREAM)
                    .withParameters(new Class[0])
                    .withGeneralOperators(generalParametersCreatorProvider, new ARC4.OperatorFactory(), null).build();
            }
        }));

        provider.addAlias("Cipher", "ARC4", PKCSObjectIdentifiers.rc4);
        provider.addAlias("Alg.Alias.Cipher.ARCFOUR", "ARC4");
        provider.addAlias("Alg.Alias.Cipher.RC4", "ARC4");
        provider.addAlgorithmImplementation("KeyGenerator.ARC4", PREFIX + "$KeyGen", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseKeyGenerator(provider, "RC4", 128, new KeyGeneratorCreator()
                {
                    public SymmetricKeyGenerator createInstance(int keySize, SecureRandom random)
                    {
                        return new ARC4.KeyGenerator(keySize, random);
                    }
                });
            }
        }));

        provider.addAlias("Alg.Alias.KeyGenerator.RC4", "ARC4");
        provider.addAlias("KeyGenerator", "ARC4", PKCSObjectIdentifiers.rc4);

        provider.addAlgorithmImplementation("Cipher.PBEWITHSHAAND40BITRC4", PREFIX + "$PBEWithSHAAnd40BitKeyFactory", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseCipher.Builder(provider, 0,ARC4.STREAM)
                    .withFixedKeySize(40)
                    .withScheme(PBEScheme.PKCS12)
                    .withGeneralOperators(generalParametersCreatorProvider, new ARC4.OperatorFactory(), null)
                    .withParameters(new Class[]{PBEParameterSpec.class}).build();
            }
        }));
        provider.addAlias("Cipher", "PBEWITHSHAAND40BITRC4", PKCSObjectIdentifiers.pbeWithSHAAnd40BitRC4);

        provider.addAlgorithmImplementation("Cipher.PBEWITHSHAAND128BITRC4", PREFIX + "$PBEWithSHAAnd128BitKeyFactory", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseCipher.Builder(provider, 0, ARC4.STREAM)
                    .withFixedKeySize(128)
                    .withScheme(PBEScheme.PKCS12)
                    .withGeneralOperators(generalParametersCreatorProvider, new ARC4.OperatorFactory(), null)
                    .withParameters(new Class[]{PBEParameterSpec.class}).build();
            }
        }));
        provider.addAlias("Cipher", "PBEWITHSHAAND128BITRC4", PKCSObjectIdentifiers.pbeWithSHAAnd128BitRC4);

        provider.addAlgorithmImplementation("SecretKeyFactory.ARC4", PREFIX + "$ARC4KFACT", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseSecretKeyFactory("RC4", ARC4.ALGORITHM, new BaseSecretKeyFactory.Validator()
                {
                    public byte[] validated(byte[] keyBytes)
                        throws InvalidKeySpecException
                    {
                        int size = keyBytes.length * 8;
                        if (size < 8 || size > 1024)
                        {
                            throw new InvalidKeySpecException("Provided key data wrong size for ARC4");
                        }

                        return keyBytes;
                    }
                });
            }
        }));
        provider.addAlias("SecretKeyFactory", "ARC4", "RC4");

        provider.addAlgorithmImplementation("SecretKeyFactory.PBEWITHSHAAND128BITRC4", PREFIX + "PBE128RC4", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new ProvPKCS12.KeyFactory("RC4", PasswordBasedDeriver.KeyType.CIPHER, 128);
            }
        }));
        provider.addAlias("SecretKeyFactory", "PBEWITHSHAAND128BITRC4", "PBEWITHSHA1AND128BITRC4", "PBEWITHSHA-1AND128BITRC4");

        provider.addAlgorithmImplementation("SecretKeyFactory.PBEWITHSHAAND40BITRC4", PREFIX + "PBE40RC4", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new ProvPKCS12.KeyFactory("RC4", PasswordBasedDeriver.KeyType.CIPHER, 40);
            }
        }));
        provider.addAlias("SecretKeyFactory", "PBEWITHSHAAND40BITRC4", "PBEWITHSHA1AND40BITRC4", "PBEWITHSHA-1AND40BITRC4");

        provider.addAlias("AlgorithmParameters", "PBKDF-PKCS12", PKCSObjectIdentifiers.pbeWithSHAAnd40BitRC4, PKCSObjectIdentifiers.pbeWithSHAAnd128BitRC4);
    }
}
