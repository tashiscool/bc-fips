package org.bouncycastle.jcajce.provider;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.SecretKey;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.crypto.AuthenticationParameters;
import org.bouncycastle.crypto.AuthenticationParametersWithIV;
import org.bouncycastle.crypto.Parameters;
import org.bouncycastle.crypto.ParametersWithIV;
import org.bouncycastle.crypto.PasswordConverter;
import org.bouncycastle.crypto.SymmetricKeyGenerator;
import org.bouncycastle.crypto.fips.FipsSHS;
import org.bouncycastle.crypto.general.DES;
import org.bouncycastle.crypto.general.SecureHash;
import org.bouncycastle.crypto.internal.ValidatedSymmetricKey;
import org.bouncycastle.crypto.internal.params.DesParameters;

final class ProvDES
    extends AlgorithmProvider
{
    ProvDES()
    {
    }

    private static final String PREFIX = ProvDES.class.getName();

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

    static class KeyFactory
        extends BaseSecretKeyFactory
    {
        KeyFactory()
        {
            super("DES", DES.ALGORITHM, new Validator()
            {
                public byte[] validated(byte[] keyBytes)
                    throws InvalidKeySpecException
                {
                    int size = keyBytes.length * 8;
                    if (size != 64)
                    {
                        throw new InvalidKeySpecException("Provided key data wrong size for DES");
                    }

                    DesParameters.setOddParity(keyBytes);

                    return keyBytes;
                }
            });
        }

        protected KeySpec engineGetKeySpec(
            SecretKey key,
            Class keySpec)
            throws InvalidKeySpecException
        {
            if (keySpec == null)
            {
                throw new InvalidKeySpecException("keySpec parameter is null");
            }
            if (key == null)
            {
                throw new InvalidKeySpecException("key parameter is null");
            }

            if (DESKeySpec.class.isAssignableFrom(keySpec))
            {
                try
                {
                    return new DESKeySpec(validator.validated(key.getEncoded()));
                }
                catch (InvalidKeyException e)
                {
                    throw new InvalidKeySpecException(e.getMessage(), e);
                }
            }

            return super.engineGetKeySpec(key, keySpec);
        }

        protected SecretKey engineGenerateSecret(
            KeySpec keySpec)
            throws InvalidKeySpecException
        {
            if (keySpec instanceof DESKeySpec)
            {
                DESKeySpec desKeySpec = (DESKeySpec)keySpec;
                return new ProvSecretKeySpec(new ValidatedSymmetricKey(DES.ALGORITHM, validator.validated(desKeySpec.getKey())));
            }

            return super.engineGenerateSecret(keySpec);
        }
    }

    public void configure(final BouncyCastleFipsProvider provider)
    {
        provider.addAlgorithmImplementation("Cipher.DES", PREFIX + "$ECB", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseCipher.Builder(provider, 64,
                    DES.ECBwithPKCS7, DES.ECB, DES.ECBwithISO10126_2, DES.ECBwithISO7816_4, DES.ECBwithTBC, DES.ECBwithX923,
                    DES.CBC, DES.CBCwithPKCS7, DES.CBCwithISO10126_2, DES.CBCwithISO7816_4, DES.CBCwithTBC, DES.CBCwithX923,
                    DES.CBCwithCS1, DES.CBCwithCS2, DES.CBCwithCS3,
                    DES.CFB64, DES.CFB8,
                    DES.OFB, DES.OpenPGPCFB,
                    DES.CTR, DES.EAX)
                    .withFixedKeySize(64)
                    .withGeneralOperators(generalParametersCreatorProvider, new DES.OperatorFactory(), new DES.AEADOperatorFactory())
                    .withParameters(availableSpecs).build();
            }
        }));
        provider.addAlgorithmImplementation("Cipher", OIWObjectIdentifiers.desCBC, PREFIX + "$CBC", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseCipher.Builder(provider, 64, DES.CBCwithPKCS7)
                    .withFixedKeySize(64)
                    .withGeneralOperators(generalParametersCreatorProvider, new DES.OperatorFactory(), null)
                    .withParameters(availableSpecs).build();
            }
        }));

        provider.addAlgorithmImplementation("KeyGenerator.DES", PREFIX + "$KeyGenerator", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseKeyGenerator(provider, "DES", 56, true, new KeyGeneratorCreator()
                {
                    public SymmetricKeyGenerator createInstance(int keySize, SecureRandom random)
                    {
                        return new DES.KeyGenerator(random);
                    }
                });
            }
        }));
        provider.addAlias("KeyGenerator", "DES", "DEA");

        provider.addAlgorithmImplementation("SecretKeyFactory.DES", PREFIX + "$KeyFactory", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new KeyFactory();
            }
        }));
        provider.addAlias("SecretKeyFactory", "DES", "DEA");

        provider.addAlgorithmImplementation("Mac.DESCMAC", PREFIX + "$CMAC", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseMac(DES.CMAC, new DES.MACOperatorFactory(), new AuthParametersCreator(DES.CMAC));
            }
        }));
        provider.addAlgorithmImplementation("Mac.DESMAC", PREFIX + "$CBCMAC", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseMac(DES.CBC_MAC, new DES.MACOperatorFactory(), new AuthParametersCreator(DES.CBC_MAC));
            }
        }));
        provider.addAlias("Alg.Alias.Mac.DES", "DESMAC");

        provider.addAlgorithmImplementation("Mac.DESMAC/CFB8", PREFIX + "$DESCFB8", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseMac(DES.CFB8_MAC, new DES.MACOperatorFactory(), new AuthParametersCreator(DES.CFB8_MAC));
            }
        }));
        provider.addAlias("Alg.Alias.Mac.DES/CFB8", "DESMAC/CFB8");

        provider.addAlgorithmImplementation("Mac.DESMAC64", PREFIX + "$DES64", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseMac(DES.CBC_MAC, new DES.MACOperatorFactory(), new MacParametersCreator()
                {
                    public AuthenticationParameters getBaseParameters()
                    {
                        return DES.CBC_MAC.withMACSize(64);
                    }

                    public AuthenticationParameters createParameters(boolean forEncryption, AlgorithmParameterSpec spec, SecureRandom random)
                        throws InvalidAlgorithmParameterException
                    {
                        return DES.CBC_MAC.withMACSize(64);
                    }
                });
            }
        }));
        provider.addAlias("Alg.Alias.Mac.DES64", "DESMAC64");

        provider.addAlgorithmImplementation("Mac.DESMAC64WITHISO7816-4PADDING", PREFIX + "$DES64with7816d4", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseMac(DES.CBC_MACwithISO7816_4, new DES.MACOperatorFactory(), new MacParametersCreator()
                {
                    public AuthenticationParameters getBaseParameters()
                    {
                        return DES.CBC_MACwithISO7816_4.withMACSize(64);
                    }

                    public AuthenticationParameters createParameters(boolean forEncryption, AlgorithmParameterSpec spec, SecureRandom random)
                        throws InvalidAlgorithmParameterException
                    {
                        return DES.CBC_MACwithISO7816_4.withMACSize(64);
                    }
                });
            }
        }));
        provider.addAlias("Mac", "DESMAC64WITHISO7816-4PADDING", "DES64WITHISO7816-4PADDING");
        provider.addAlias("Mac", "DESMAC64WITHISO7816-4PADDING", "DESISO9797ALG1MACWITHISO7816-4PADDING");
        provider.addAlias("Mac", "DESMAC64WITHISO7816-4PADDING", "DESISO9797ALG1WITHISO7816-4PADDING");

        provider.addAlgorithmImplementation("Mac.DESWITHISO9797", PREFIX + "$DES9797Alg3", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseMac(DES.ISO9797alg3Mac, new DES.MACOperatorFactory(), new MacParametersCreator()
                {
                    public AuthenticationParameters getBaseParameters()
                    {
                        return DES.ISO9797alg3Mac;
                    }

                    public AuthenticationParameters createParameters(boolean forEncryption, AlgorithmParameterSpec spec, SecureRandom random)
                        throws InvalidAlgorithmParameterException
                    {
                        return DES.ISO9797alg3Mac;
                    }
                });
            }
        }));
        provider.addAlias("Mac", "DESWITHISO9797", "DESISO9797MAC", "ISO9797ALG3", "ISO9797ALG3MAC");

        provider.addAlgorithmImplementation("Mac.ISO9797ALG3WITHISO7816-4PADDING", PREFIX + "$DES9797Alg3with7816d4", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseMac(DES.ISO9797alg3MACwithISO7816_4, new DES.MACOperatorFactory(), new MacParametersCreator()
                {
                    public AuthenticationParameters getBaseParameters()
                    {
                        return DES.ISO9797alg3MACwithISO7816_4.withMACSize(64);
                    }

                    public AuthenticationParameters createParameters(boolean forEncryption, AlgorithmParameterSpec spec, SecureRandom random)
                        throws InvalidAlgorithmParameterException
                    {
                        return DES.ISO9797alg3MACwithISO7816_4.withMACSize(64);
                    }
                });
            }
        }));
        provider.addAlias("Alg.Alias.Mac.ISO9797ALG3MACWITHISO7816-4PADDING", "ISO9797ALG3WITHISO7816-4PADDING");

        provider.addAlgorithmImplementation("AlgorithmParameters.DES", PREFIX + ".util.IvAlgorithmParameters", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new IvAlgorithmParameters();
            }
        }));

        provider.addAlias("AlgorithmParameters", "DES", OIWObjectIdentifiers.desCBC);

        provider.addAlgorithmImplementation("AlgorithmParameterGenerator", OIWObjectIdentifiers.desCBC, PREFIX + "$AlgParamGen", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new IVAlgorithmParameterGenerator(provider, "DES", 8);
            }
        }));

        provider.addAlgorithmImplementation("Cipher.PBEWITHMD5ANDDES-CBC", PREFIX + "$PBEWithMD5", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseCipher.Builder(provider, 64, DES.CBCwithPKCS7)
                    .withGeneralOperators(generalParametersCreatorProvider, new DES.OperatorFactory(), null)
                    .withFixedKeySize(64)
                    .withScheme(PBEScheme.PBKDF1)
                    .withPrf(SecureHash.Algorithm.MD5)
                    .withParameters(availableSpecs).build();
            }
        }));
        provider.addAlgorithmImplementation("Cipher.PBEWITHSHA1ANDDES-CBC", PREFIX + "$PBEWithSHA1", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseCipher.Builder(provider, 64, DES.CBCwithPKCS7)
                    .withGeneralOperators(generalParametersCreatorProvider, new DES.OperatorFactory(), null)
                    .withFixedKeySize(64)
                    .withScheme(PBEScheme.PBKDF1)
                    .withPrf(FipsSHS.Algorithm.SHA1)
                    .withParameters(availableSpecs).build();
            }
        }));

        provider.addAlias("Cipher", "PBEWITHMD5ANDDES-CBC", "PBEWITHMD5ANDDES");
        provider.addAlias("Cipher", "PBEWITHSHA1ANDDES-CBC", "PBEWITHSHA1ANDDES");
        provider.addAlias("Cipher", "PBEWITHMD5ANDDES-CBC", PKCSObjectIdentifiers.pbeWithMD5AndDES_CBC);
        provider.addAlias("Cipher", "PBEWITHSHA1ANDDES-CBC", PKCSObjectIdentifiers.pbeWithSHA1AndDES_CBC);

        provider.addAlgorithmImplementation("SecretKeyFactory.PBEWITHSHAANDDES", PREFIX + "PBESHADES", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new ProvPBEPBKDF1.FixedPBKDF1("DES", PasswordConverter.ASCII, FipsSHS.Algorithm.SHA1, 64);
            }
        }));
        provider.addAlias("SecretKeyFactory", "PBEWITHSHAANDDES", "PBEWITHSHA1ANDDES", "PBEWITHSHA-1ANDDES");

        provider.addAlgorithmImplementation("SecretKeyFactory.PBEWITHMD5ANDDES", PREFIX + "PBEMD5DES", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new ProvPBEPBKDF1.FixedPBKDF1("DES", PasswordConverter.ASCII, SecureHash.Algorithm.MD5, 64);
            }
        }));

        addAlias(provider, OIWObjectIdentifiers.desCBC, "DES");
    }

    private void addAlias(BouncyCastleFipsProvider provider, ASN1ObjectIdentifier oid, String name)
    {
        provider.addAlias("KeyGenerator", name, oid);
    }
}
