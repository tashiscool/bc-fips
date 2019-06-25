package org.bouncycastle.jcajce.provider;

import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.SecretKey;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEParameterSpec;

import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.crypto.AuthenticationParameters;
import org.bouncycastle.crypto.AuthenticationParametersWithIV;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.Parameters;
import org.bouncycastle.crypto.ParametersWithIV;
import org.bouncycastle.crypto.PasswordBasedDeriver;
import org.bouncycastle.crypto.SymmetricKeyGenerator;
import org.bouncycastle.crypto.fips.FipsParameters;
import org.bouncycastle.crypto.fips.FipsTripleDES;
import org.bouncycastle.crypto.general.TripleDES;
import org.bouncycastle.crypto.internal.ValidatedSymmetricKey;
import org.bouncycastle.crypto.internal.params.DesParameters;
import org.bouncycastle.jcajce.spec.WrapParameterSpec;

final class ProvDESede
    extends AlgorithmProvider
{
    private static final Map<String, String> generalDesEdeAttributes = new HashMap<String, String>();

    static
    {
        generalDesEdeAttributes.put("SupportedKeyClasses", "javax.crypto.SecretKey");
        generalDesEdeAttributes.put("SupportedKeyFormats", "RAW");
    }

    private FipsTripleDES.OperatorFactory fipsOperatorFactory;
    private FipsTripleDES.KeyWrapOperatorFactory fipsKeyWrapOperatorFactory;

    ProvDESede()
    {
        fipsOperatorFactory = new FipsTripleDES.OperatorFactory();
        fipsKeyWrapOperatorFactory = new FipsTripleDES.KeyWrapOperatorFactory();
    }

    static class KeyFactory
        extends BaseSecretKeyFactory
    {
        KeyFactory()
        {
            super("DESede", FipsTripleDES.ALGORITHM, new Validator()
            {
                public byte[] validated(byte[] keyBytes)
                    throws InvalidKeySpecException
                {
                    int size = keyBytes.length * 8;
                    if (size != 128 && size != 192)
                    {
                        throw new InvalidKeySpecException("Provided key data wrong size for DESede");
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

            if (DESedeKeySpec.class.isAssignableFrom(keySpec))
            {
                byte[] bytes = key.getEncoded();

                try
                {
                    if (bytes.length == 16)
                    {
                        byte[] longKey = new byte[24];

                        System.arraycopy(bytes, 0, longKey, 0, 16);
                        System.arraycopy(bytes, 0, longKey, 16, 8);

                        return new DESedeKeySpec(longKey); // no need to validate
                    }
                    else
                    {
                        return new DESedeKeySpec(validator.validated(bytes));
                    }
                }
                catch (Exception e)
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
            if (keySpec instanceof DESedeKeySpec)
            {
                DESedeKeySpec desKeySpec = (DESedeKeySpec)keySpec;
                return new ProvSecretKeySpec(new ValidatedSymmetricKey(FipsTripleDES.ALGORITHM, validator.validated(desKeySpec.getKey())));
            }

            return super.engineGenerateSecret(keySpec);
        }
    }

    private static final String PREFIX = ProvDESede.class.getName() + ".";

    private Class[] availableSpecs =
        {
            IvParameterSpec.class,
        };

    private ParametersCreatorProvider<FipsParameters> fipsParametersCreatorProvider = new ParametersCreatorProvider<FipsParameters>()
    {
        public ParametersCreator get(final FipsParameters parameters)
        {
            if (Utils.isAuthMode(parameters.getAlgorithm()))
            {
                return new AuthParametersCreator((AuthenticationParametersWithIV)parameters);
            }
            else if (parameters.getAlgorithm().equals(FipsTripleDES.TKW.getAlgorithm()))
            {
                return new ParametersCreator()
                {

                    public Parameters createParameters(boolean forEncryption, AlgorithmParameterSpec spec, SecureRandom random)
                        throws InvalidAlgorithmParameterException
                    {
                        if (spec instanceof WrapParameterSpec)
                        {
                            return ((FipsTripleDES.WrapParameters)parameters).withUsingInverseFunction(((WrapParameterSpec)spec).useInverseFunction());
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


    public void configure(final BouncyCastleFipsProvider provider)
    {
        provider.addAlgorithmImplementation("Cipher.DESEDE", PREFIX + "$ECB", generalDesEdeAttributes, new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                if (CryptoServicesRegistrar.isInApprovedOnlyMode())
                {
                    return new BaseCipher.Builder(provider, 64,
                        FipsTripleDES.ECBwithPKCS7, FipsTripleDES.ECB, FipsTripleDES.ECBwithISO10126_2, FipsTripleDES.ECBwithISO7816_4, FipsTripleDES.ECBwithTBC, FipsTripleDES.ECBwithX923,
                        FipsTripleDES.CBC, FipsTripleDES.CBCwithPKCS7, FipsTripleDES.CBCwithISO10126_2, FipsTripleDES.CBCwithISO7816_4, FipsTripleDES.CBCwithTBC, FipsTripleDES.CBCwithX923,
                        FipsTripleDES.CBCwithCS1, FipsTripleDES.CBCwithCS2, FipsTripleDES.CBCwithCS3,
                        FipsTripleDES.CFB64, FipsTripleDES.CFB8,
                        FipsTripleDES.OFB,
                        FipsTripleDES.CTR)
                        .withFipsOperators(fipsParametersCreatorProvider, fipsOperatorFactory, null)
                        .withParameters(availableSpecs).build();
                }
                else
                {
                    return new BaseCipher.Builder(provider, 64,
                        FipsTripleDES.ECBwithPKCS7, FipsTripleDES.ECB, FipsTripleDES.ECBwithISO10126_2, FipsTripleDES.ECBwithISO7816_4, FipsTripleDES.ECBwithTBC, FipsTripleDES.ECBwithX923,
                        FipsTripleDES.CBC, FipsTripleDES.CBCwithPKCS7, FipsTripleDES.CBCwithISO10126_2, FipsTripleDES.CBCwithISO7816_4, FipsTripleDES.CBCwithTBC, FipsTripleDES.CBCwithX923,
                        FipsTripleDES.CBCwithCS1, FipsTripleDES.CBCwithCS2, FipsTripleDES.CBCwithCS3,
                        FipsTripleDES.CFB64, FipsTripleDES.CFB8,
                        FipsTripleDES.OFB,
                        FipsTripleDES.CTR, TripleDES.OpenPGPCFB, TripleDES.EAX)
                        .withFipsOperators(fipsParametersCreatorProvider, fipsOperatorFactory, null)
                        .withGeneralOperators(generalParametersCreatorProvider, null, new TripleDES.AEADOperatorFactory())
                        .withParameters(availableSpecs).build();
                }
            }
        });
        provider.addAlgorithmImplementation("Cipher", PKCSObjectIdentifiers.des_EDE3_CBC, PREFIX + "$CBC", generalDesEdeAttributes, new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseCipher.Builder(provider, 64, FipsTripleDES.CBCwithPKCS7)
                    .withFipsOperators(fipsParametersCreatorProvider, fipsOperatorFactory, null)
                    .withParameters(availableSpecs).build();
            }
        });
        provider.addAlgorithmImplementation("Cipher.DESEDEWRAP", PREFIX + "$Wrap", generalDesEdeAttributes, new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseWrapCipher.Builder(provider, FipsTripleDES.TKW)
                    .withFipsOperators(fipsParametersCreatorProvider, fipsKeyWrapOperatorFactory)
                    .withParameters(availableSpecs).build();
            }
        });
        provider.addAlias("Alg.Alias.Cipher.DESEDETKW", "DESEDEWRAP");

        if (!CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            provider.addAlgorithmImplementation("Cipher.DESEDERFC3217WRAP", PREFIX + "$RFC3217Wrap", generalDesEdeAttributes, new GuardedEngineCreator(new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new BaseWrapCipher.Builder(provider, TripleDES.RFC3217_WRAP)
                        .withGeneralOperators(generalParametersCreatorProvider, new TripleDES.KeyWrapOperatorFactory())
                        .withParameters(availableSpecs).build();
                }
            }));
            provider.addAlias("Cipher", "DESEDERFC3217WRAP", PKCSObjectIdentifiers.id_alg_CMS3DESwrap);

            provider.addAlgorithmImplementation("Cipher.DESEDERFC3211WRAP", PREFIX + "$RFC3211Wrap", generalDesEdeAttributes, new GuardedEngineCreator(new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new BaseWrapCipher.Builder(provider, TripleDES.RFC3211_WRAP)
                        .withGeneralOperators(generalParametersCreatorProvider, new TripleDES.KeyWrapOperatorFactory())
                        .withParameters(availableSpecs).build();
                }
            }));

            provider.addAlgorithmImplementation("Cipher.DESEDE/OPENPGPCFB/NOPADDING", PREFIX + "$OpenPGP", generalDesEdeAttributes, new GuardedEngineCreator(new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new BaseCipher.Builder(provider, 64, TripleDES.OpenPGPCFB)
                        .withGeneralOperators(generalParametersCreatorProvider, new TripleDES.OperatorFactory(), null)
                        .withParameters(availableSpecs).build();
                }
            }));

            provider.addAlgorithmImplementation("Cipher.PBEWITHSHAAND3-KEYDESEDE-CBC", PREFIX + "$PBEWithSHAAndDES3Key", new GuardedEngineCreator(new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new BaseCipher.Builder(provider, 64, FipsTripleDES.CBCwithPKCS7)
                        .withFixedKeySize(192)
                        .withScheme(PBEScheme.PKCS12)
                        .withFipsOperators(fipsParametersCreatorProvider, fipsOperatorFactory, null)
                        .withParameters(new Class[]{PBEParameterSpec.class}).build();
                }
            }));

            provider.addAlgorithmImplementation("Cipher.PBEWITHSHAAND2-KEYDESEDE-CBC", PREFIX + "$PBEWithSHAAndDES2Key", new GuardedEngineCreator(new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new BaseCipher.Builder(provider, 64, FipsTripleDES.CBCwithPKCS7)
                        .withFixedKeySize(128)
                        .withScheme(PBEScheme.PKCS12)
                        .withFipsOperators(fipsParametersCreatorProvider, fipsOperatorFactory, null)
                        .withParameters(new Class[]{PBEParameterSpec.class}).build();
                }
            }));

            provider.addAlias("Cipher", "PBEWITHSHAAND3-KEYDESEDE-CBC", PKCSObjectIdentifiers.pbeWithSHAAnd3_KeyTripleDES_CBC);
            provider.addAlias("Cipher", "PBEWITHSHAAND3-KEYDESEDE-CBC", "PBEWITHSHA1ANDDESEDE", "PBEWITHSHAAND3KEYTRIPLEDES");
            provider.addAlias("Cipher", "PBEWITHSHAAND2-KEYDESEDE-CBC", PKCSObjectIdentifiers.pbeWithSHAAnd2_KeyTripleDES_CBC);
            provider.addAlias("Cipher", "PBEWITHSHAAND2-KEYDESEDE-CBC", "PBEWITHSHAAND2KEYTRIPLEDES");
            provider.addAlias("Alg.Alias.Cipher.PBEWITHSHA1ANDDESEDE-CBC", "PBEWITHSHAAND3-KEYDESEDE-CBC");
            provider.addAlias("Alg.Alias.Cipher.PBEWITHSHAAND3-KEYTRIPLEDES-CBC", "PBEWITHSHAAND3-KEYDESEDE-CBC");
            provider.addAlias("Alg.Alias.Cipher.PBEWITHSHAAND2-KEYTRIPLEDES-CBC", "PBEWITHSHAAND2-KEYDESEDE-CBC");
            provider.addAlias("Alg.Alias.Cipher.PBEWITHSHA1AND3-KEYTRIPLEDES-CBC", "PBEWITHSHAAND3-KEYDESEDE-CBC");
            provider.addAlias("Alg.Alias.Cipher.PBEWITHSHA1AND2-KEYTRIPLEDES-CBC", "PBEWITHSHAAND2-KEYDESEDE-CBC");
        }

        provider.addAlgorithmImplementation("KeyGenerator.DESEDE", PREFIX + "$KeyGenerator", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseKeyGenerator(provider, "DESede", 168, new KeyGeneratorCreator()
                {
                    public SymmetricKeyGenerator createInstance(int keySize, SecureRandom random)
                    {
                        return new FipsTripleDES.KeyGenerator(keySize, random);
                    }
                });
            }
        });
        provider.addAlias("KeyGenerator", "DESEDE", "TRIPLEDES");
        provider.addAlias("KeyGenerator", "DESEDE", OIWObjectIdentifiers.desEDE);

        provider.addAlgorithmImplementation("KeyGenerator", PKCSObjectIdentifiers.des_EDE3_CBC, PREFIX + "$KeyGenerator3", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseKeyGenerator(provider, "DESede", 168, true, new KeyGeneratorCreator()
                {
                    public SymmetricKeyGenerator createInstance(int keySize, SecureRandom random)
                    {
                        return new FipsTripleDES.KeyGenerator(FipsTripleDES.CBC, 168, random);
                    }
                });
            }
        });

        provider.addAlgorithmImplementation("Mac.DESEDECMAC", PREFIX + "$CMAC", generalDesEdeAttributes, new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseMac(FipsTripleDES.CMAC, new FipsTripleDES.MACOperatorFactory(), new AuthParametersCreator(FipsTripleDES.CMAC));
            }
        });
        provider.addAlias("Mac", "DESEDECMAC", "DESEDE-CMAC");

        provider.addAlgorithmImplementation("AlgorithmParameters.DESEDE", PREFIX + ".util.IvAlgorithmParameters", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new IvAlgorithmParameters();
            }
        });
        provider.addAlias("AlgorithmParameters", "DESEDE", PKCSObjectIdentifiers.des_EDE3_CBC);

        provider.addAlgorithmImplementation("AlgorithmParameterGenerator", PKCSObjectIdentifiers.des_EDE3_CBC, PREFIX + "$AlgParamGen", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new IVAlgorithmParameterGenerator(provider, "DESede", 8);
            }
        });

        provider.addAlgorithmImplementation("SecretKeyFactory.DESEDE", PREFIX + "$KeyFactory", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new KeyFactory();
            }
        });
        provider.addAlias("SecretKeyFactory", "DESEDE", "TDEA", "TRIPLEDES");

        provider.addAlias("Cipher", "DESEDE", "TDEA");
        provider.addAlias("Cipher", "DESEDEWRAP", "TDEAWRAP");
        provider.addAlias("KeyGenerator", "DESEDE", "TDEA");
        provider.addAlias("AlgorithmParameters", "DESEDE", "TDEA");

        if (!CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            provider.addAlgorithmImplementation("Mac.DESEDEMAC", PREFIX + "$CBCMAC", generalDesEdeAttributes, new GuardedEngineCreator(new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new BaseMac(TripleDES.CBC_MAC, new TripleDES.MACOperatorFactory(), new AuthParametersCreator(TripleDES.CBC_MAC));
                }
            }));
            provider.addAlias("Alg.Alias.Mac.DESEDE", "DESEDEMAC");

            provider.addAlgorithmImplementation("Mac.DESEDEMAC/CFB8", PREFIX + "$DESedeCFB8", generalDesEdeAttributes, new GuardedEngineCreator(new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new BaseMac(TripleDES.CFB8_MAC, new TripleDES.MACOperatorFactory(), new AuthParametersCreator(TripleDES.CFB8_MAC));
                }
            }));
            provider.addAlias("Mac", "DESEDEMAC/CFB8", "DESEDE/CFB8");

            provider.addAlgorithmImplementation("Mac.DESEDEMAC64", PREFIX + "$DESede64", generalDesEdeAttributes, new GuardedEngineCreator(new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new BaseMac(TripleDES.CBC_MAC, new TripleDES.MACOperatorFactory(), new MacParametersCreator()
                    {
                        public AuthenticationParameters getBaseParameters()
                        {
                            return TripleDES.CBC_MAC.withMACSize(64);
                        }

                        public AuthenticationParameters createParameters(boolean forEncryption, AlgorithmParameterSpec spec, SecureRandom random)
                            throws InvalidAlgorithmParameterException
                        {
                            return TripleDES.CBC_MAC.withMACSize(64);
                        }
                    });
                }
            }));

            provider.addAlias("Mac", "DESEDEMAC64", "DESEDE64");

            provider.addAlgorithmImplementation("Mac.DESEDEMAC64WITHISO7816-4PADDING", PREFIX + "$DESede64with7816d4", generalDesEdeAttributes, new GuardedEngineCreator(new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new BaseMac(TripleDES.CBC_MACwithISO7816_4, new TripleDES.MACOperatorFactory(), new MacParametersCreator()
                    {
                        public AuthenticationParameters getBaseParameters()
                        {
                            return TripleDES.CBC_MACwithISO7816_4.withMACSize(64);
                        }

                        public AuthenticationParameters createParameters(boolean forEncryption, AlgorithmParameterSpec spec, SecureRandom random)
                            throws InvalidAlgorithmParameterException
                        {
                            return TripleDES.CBC_MACwithISO7816_4.withMACSize(64);
                        }
                    });
                }
            }));
            provider.addAlias("Mac", "DESEDEMAC64WITHISO7816-4PADDING", "DESEDE64WITHISO7816-4PADDING");
            provider.addAlias("Mac", "DESEDEMAC64WITHISO7816-4PADDING", "DESEDEISO9797ALG1MACWITHISO7816-4PADDING");
            provider.addAlias("Mac", "DESEDEMAC64WITHISO7816-4PADDING", "DESEDEISO9797ALG1WITHISO7816-4PADDING");

            provider.addAlgorithmImplementation("SecretKeyFactory.PBEWITHSHAAND2-KEYTRIPLEDES", PREFIX + "$PBEWithSHAAndDES2KeyFactory", new GuardedEngineCreator(new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new ProvPKCS12.KeyFactory("DESede", PasswordBasedDeriver.KeyType.CIPHER, 128);
                }
            }));

            provider.addAlias("SecretKeyFactory", "PBEWITHSHAAND2-KEYTRIPLEDES",
                "PBEWITHSHA1AND2-KEYTRIPLEDES", "PBEWITHSHA-1AND2-KEYTRIPLEDES",
                "PBEWITHSHAAND2-KEYDESEDE", "PBEWITHSHA1AND2-KEYDESEDE", "PBEWITHSHA-1AND2-KEYDESEDE");

            provider.addAlgorithmImplementation("SecretKeyFactory.PBEWITHSHAAND3-KEYTRIPLEDES", PREFIX + "$PBEWithSHAAndDES3KeyFactory", new GuardedEngineCreator(new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new ProvPKCS12.KeyFactory("DESede", PasswordBasedDeriver.KeyType.CIPHER, 192);
                }
            }));
            provider.addAlias("SecretKeyFactory", "PBEWITHSHAAND3-KEYTRIPLEDES",
                "PBEWITHSHA1AND3-KEYTRIPLEDES", "PBEWITHSHA-1AND3-KEYTRIPLEDES",
                "PBEWITHSHAAND3-KEYDESEDE", "PBEWITHSHA1AND3-KEYDESEDE", "PBEWITHSHA-1AND3-KEYDESEDE");
            provider.addAlias("SecretKeyFactory", "DESEDE", OIWObjectIdentifiers.desEDE);

            provider.addAlias("AlgorithmParameters", "PBKDF-PKCS12", PKCSObjectIdentifiers.pbeWithSHAAnd2_KeyTripleDES_CBC, PKCSObjectIdentifiers.pbeWithSHAAnd3_KeyTripleDES_CBC);
        }
    }
}
