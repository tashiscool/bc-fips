package org.bouncycastle.jcajce.provider;


import java.lang.reflect.Constructor;
import java.security.AccessController;
import java.security.InvalidAlgorithmParameterException;
import java.security.PrivilegedAction;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.KDFCalculator;
import org.bouncycastle.crypto.fips.FipsKDF;
import org.bouncycastle.crypto.fips.FipsKDF.TLSPRF;
import org.bouncycastle.util.Arrays;
import sun.security.internal.spec.TlsKeyMaterialParameterSpec;
import sun.security.internal.spec.TlsKeyMaterialSpec;
import sun.security.internal.spec.TlsMasterSecretParameterSpec;
import sun.security.internal.spec.TlsPrfParameterSpec;
import sun.security.internal.spec.TlsRsaPremasterSecretParameterSpec;

class ProvSunTLSKDF
    extends AsymmetricAlgorithmProvider
{
    private static final boolean hasPrfMethods;                             // for JDK 1.6
    private static final Constructor tlsPrfParameterSpecConstructor;        // for JDK 1.6
    private static final boolean hasGetEncodeSecretMethod;                  // introduced late in JDK 1,8

    static
    {
        hasPrfMethods = AccessController.doPrivileged(new PrivilegedAction<Boolean>()
        {
            public Boolean run()
            {
                try
                {
                    Class def = BouncyCastleFipsProvider.class.getClassLoader().loadClass("sun.security.internal.spec.TlsPrfParameterSpec");

                    return def.getMethod("getPRFHashAlg") != null;
                }
                catch (Exception e)
                {
                    return false;
                }
            }
        });
        hasGetEncodeSecretMethod = AccessController.doPrivileged(new PrivilegedAction<Boolean>()
        {
            public Boolean run()
            {
                try
                {
                    Class def = BouncyCastleFipsProvider.class.getClassLoader().loadClass("sun.security.internal.spec.TlsRsaPremasterSecretParameterSpec");

                    return def.getMethod("getEncodedSecret") != null;
                }
                catch (Exception e)
                {
                    return false;
                }
            }
        });
        tlsPrfParameterSpecConstructor = AccessController.doPrivileged(new PrivilegedAction<Constructor>()
        {
            public Constructor run()
            {
                try
                {
                    Class def = BouncyCastleFipsProvider.class.getClassLoader().loadClass("sun.security.internal.spec.TlsPrfParameterSpec");

                    return def.getConstructors()[0];
                }
                catch (Exception e)
                {
                    return null;
                }
            }
        });
    }


    private static final String PROVIDER_PACKAGE = "org.bouncycastle.jcajce.provider.";
    private static final String SYMMETRIC_PACKAGE = PROVIDER_PACKAGE + "symmetric.";
    private static final String KDF_PACKAGE = SYMMETRIC_PACKAGE + "kdf.";

    public void configure(final BouncyCastleFipsProvider provider)
    {
        provider.addAlgorithmImplementation("KeyGenerator.SUNTLSRSAPREMASTERSECRET", KDF_PACKAGE + "SunTLSKeyGeneratorPremaster", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new TLSRsaPreMasterSecretGenerator();
            }
        });
        provider.addAlgorithmImplementation("KeyGenerator.SUNTLS12RSAPREMASTERSECRET", KDF_PACKAGE + "SunTLS12KeyGeneratorPremaster", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new TLSRsaPreMasterSecretGenerator();
            }
        });
        provider.addAlgorithmImplementation("KeyGenerator.SUNTLSMASTERSECRET", KDF_PACKAGE + "SunTLSKeyGeneratorMaster", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new TLSMasterSecretGenerator();
            }
        });
        provider.addAlgorithmImplementation("KeyGenerator.SUNTLS12MASTERSECRET", KDF_PACKAGE + "SunTLS12KeyGeneratorMaster", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new TLSMasterSecretGenerator();
            }
        });
        provider.addAlgorithmImplementation("KeyGenerator.SUNTLSKEYMATERIAL", KDF_PACKAGE + "SunTLSKeyGeneratorKeyMaterial", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new TLSKeyMaterialGenerator();
            }
        });
        provider.addAlgorithmImplementation("KeyGenerator.SUNTLS12KEYMATERIAL", KDF_PACKAGE + "SunTLS12KeyGeneratorKeyMaterial", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new TLSKeyMaterialGenerator();
            }
        });
        provider.addAlgorithmImplementation("KeyGenerator.SUNTLSPRF", KDF_PACKAGE + "SunTLSKeyGeneratorPRF", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new TLSPRFKeyGenerator();
            }
        });
        provider.addAlgorithmImplementation("KeyGenerator.SUNTLS12PRF", KDF_PACKAGE + "SunTLS12KeyGeneratorPRF", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new TLSPRFKeyGenerator();
            }
        });
    }


    static abstract class BaseTLSKeyGeneratorSpi
        extends KeyGeneratorSpi
    {
        protected SecureRandom secureRandom = null;

        @Override
        protected void engineInit(SecureRandom secureRandom)
        {
            throw new UnsupportedOperationException();
        }

        @Override
        protected void engineInit(int keySize, SecureRandom secureRandom)
        {
            throw new UnsupportedOperationException();
        }

        protected SecretKey calculatePRF(TlsPrfParameterSpec spec, String keyAlg)
        {
            FipsKDF.TLSParametersBuilder pBld;
            if (hasPrfMethods)
            {
                TLSPRF prf = getPRF(spec.getPRFHashAlg());
                pBld = (prf == null)
                    ? FipsKDF.TLS1_1
                    : FipsKDF.TLS1_2.withPRF(prf);
            }
            else
            {
                pBld =  FipsKDF.TLS1_1;
            }
            FipsKDF.TLSParameters tlsParams = pBld.using(spec.getSecret().getEncoded(),
                spec.getLabel(), spec.getSeed());
            KDFCalculator kdfCalculator = new FipsKDF.TLSOperatorFactory().createKDFCalculator(tlsParams);

            byte[] prfOutput = new byte[spec.getOutputLength()];
            kdfCalculator.generateBytes(prfOutput);

            return new SecretKeySpec(prfOutput, keyAlg);
        }
    }

    final static class TLSRsaPreMasterSecretGenerator
        extends BaseTLSKeyGeneratorSpi
    {
        private TlsRsaPremasterSecretParameterSpec spec;

        @Override
        protected void engineInit(final AlgorithmParameterSpec algorithmParameterSpec, final SecureRandom secureRandom)
            throws InvalidAlgorithmParameterException
        {
            AccessController.doPrivileged(new PrivilegedAction<Object>()
            {
                public Object run()
                {
                    TLSRsaPreMasterSecretGenerator.this.spec = (TlsRsaPremasterSecretParameterSpec)algorithmParameterSpec;
                    TLSRsaPreMasterSecretGenerator.this.secureRandom = secureRandom;

                    return null;
                }
            });
        }

        @Override
        protected SecretKey engineGenerateKey()
        {
            return AccessController.doPrivileged(new PrivilegedAction<SecretKey>()
            {
                public SecretKey run()
                {
                    if (hasGetEncodeSecretMethod)
                    {
                        try
                        {
                            Class def = BouncyCastleFipsProvider.class.getClassLoader().loadClass("sun.security.internal.spec.TlsRsaPremasterSecretParameterSpec");

                            byte[] premasterSecret = (byte[])def.getMethod("getEncodedSecret").invoke(TLSRsaPreMasterSecretGenerator.this.spec);
                            if (premasterSecret == null)     // fallback to old method
                            {
                                premasterSecret = new byte[48];
                                secureRandom.nextBytes(premasterSecret);

                                premasterSecret[0] = (byte)spec.getMajorVersion();
                                premasterSecret[1] = (byte)spec.getMinorVersion();
                            }

                            return new SecretKeySpec(premasterSecret, "TlsPreMasterSecret");
                        }
                        catch (Exception e)
                        {
                            throw new IllegalStateException("internal error, profile of TlsRSAPremasterSecretParameterSpec has changed: " + e.getMessage(), e);
                        }
                    }
                    else
                    {
                        byte[] premasterSecret = new byte[48];
                        secureRandom.nextBytes(premasterSecret);

                        premasterSecret[0] = (byte)spec.getMajorVersion();
                        premasterSecret[1] = (byte)spec.getMinorVersion();

                        return new SecretKeySpec(premasterSecret, "TlsPreMasterSecret");
                    }
                }
            });
        }
    }

    final static class TLSMasterSecretGenerator
        extends BaseTLSKeyGeneratorSpi
    {
        private TlsMasterSecretParameterSpec spec;

        @Override
        protected void engineInit(final AlgorithmParameterSpec algorithmParameterSpec, final SecureRandom secureRandom)
            throws InvalidAlgorithmParameterException
        {
            AccessController.doPrivileged(new PrivilegedAction<Object>()
            {
                public Object run()
                {
                    TLSMasterSecretGenerator.this.spec = (TlsMasterSecretParameterSpec)algorithmParameterSpec;
                    TLSMasterSecretGenerator.this.secureRandom = secureRandom;

                    return null;
                }
            });
        }

        @Override
        protected SecretKey engineGenerateKey()
        {
            return AccessController.doPrivileged(new PrivilegedAction<SecretKey>()
            {
                public SecretKey run()
                {
                    byte[] seed = Arrays.concatenate(spec.getClientRandom(), spec.getServerRandom());

                    TlsPrfParameterSpec prfSpec;

                    if (hasPrfMethods)
                    {
                        prfSpec = createPrfParameterSpec(spec.getPremasterSecret(), FipsKDF.TLSStage.MASTER_SECRET, seed, 48,
                                                                        spec.getPRFHashAlg(), spec.getPRFHashLength(), spec.getPRFBlockSize());
                    }
                    else
                    {
                        prfSpec = createPrfParameterSpec(spec.getPremasterSecret(), FipsKDF.TLSStage.MASTER_SECRET, seed, 48,
                                                                         null, 0, 0);
                    }
                    return calculatePRF(prfSpec, "TlsMasterSecret");
                }
            });
        }
    }

    final static class TLSKeyMaterialGenerator
        extends BaseTLSKeyGeneratorSpi
    {
        private TlsKeyMaterialParameterSpec spec;

        @Override
        protected void engineInit(final AlgorithmParameterSpec algorithmParameterSpec, final SecureRandom secureRandom)
            throws InvalidAlgorithmParameterException
        {
            AccessController.doPrivileged(new PrivilegedAction<Object>()
            {
                public Object run()
                {
                    TLSKeyMaterialGenerator.this.spec = (TlsKeyMaterialParameterSpec)algorithmParameterSpec;
                    TLSKeyMaterialGenerator.this.secureRandom = secureRandom;

                    return null;
                }
            });
        }

        @Override
        protected SecretKey engineGenerateKey()
        {
            return AccessController.doPrivileged(new PrivilegedAction<SecretKey>()
            {
                public SecretKey run()
                {
                    if (spec.getExpandedCipherKeyLength() > 0)
                    {
                        // TODO spec.getExpandedCipherKeyLength() is apparently related to "exportable ciphersuites"
                        throw new UnsupportedOperationException();
                    }

                    int cipherKeyLength = spec.getCipherKeyLength();
                    int ivLength = spec.getIvLength();
                    int macKeyLength = spec.getMacKeyLength();

                    int total = (cipherKeyLength + ivLength + macKeyLength) * 2;

                    byte[] seed = Arrays.concatenate(spec.getServerRandom(), spec.getClientRandom());

                    TlsPrfParameterSpec prfSpec;
                    if (hasPrfMethods)
                    {
                        prfSpec = createPrfParameterSpec(spec.getMasterSecret(), FipsKDF.TLSStage.KEY_EXPANSION, seed, total,
                            spec.getPRFHashAlg(), spec.getPRFHashLength(), spec.getPRFBlockSize());
                    }
                    else
                    {
                        prfSpec = createPrfParameterSpec(spec.getMasterSecret(), FipsKDF.TLSStage.KEY_EXPANSION, seed, total,
                                                null, 0, 0);
                    }

                    byte[] keyMaterial = calculatePRF(prfSpec, "DUMMY").getEncoded();

                    SecretKey clientMacKey = null, serverMacKey = null;
                    SecretKey clientCipherKey = null, serverCipherKey = null;
                    IvParameterSpec clientIv = null, serverIv = null;

                    int offset = 0;

                    if (macKeyLength > 0)
                    {
                        String macAlgorithm = "DUMMY";
                        clientMacKey = new SecretKeySpec(keyMaterial, offset, macKeyLength, macAlgorithm);
                        offset += macKeyLength;
                        serverMacKey = new SecretKeySpec(keyMaterial, offset, macKeyLength, macAlgorithm);
                        offset += macKeyLength;
                    }

                    if (cipherKeyLength > 0)
                    {
                        String cipherAlgorithm = spec.getCipherAlgorithm();
                        clientCipherKey = new SecretKeySpec(keyMaterial, offset, cipherKeyLength, cipherAlgorithm);
                        offset += cipherKeyLength;
                        serverCipherKey = new SecretKeySpec(keyMaterial, offset, cipherKeyLength, cipherAlgorithm);
                        offset += cipherKeyLength;
                    }

                    if (ivLength > 0)
                    {
                        clientIv = new IvParameterSpec(keyMaterial, offset, ivLength);
                        offset += ivLength;
                        serverIv = new IvParameterSpec(keyMaterial, offset, ivLength);
                        offset += ivLength;
                    }

                    if (offset != total)
                    {
                        throw new IllegalStateException();
                    }

                    return new TlsKeyMaterialSpec(clientMacKey, serverMacKey, clientCipherKey, clientIv, serverCipherKey, serverIv);
                }
            });
        }
    }

    final static class TLSPRFKeyGenerator
        extends BaseTLSKeyGeneratorSpi
    {
        private TlsPrfParameterSpec spec;

        @Override
        protected void engineInit(final AlgorithmParameterSpec algorithmParameterSpec, final SecureRandom secureRandom)
            throws InvalidAlgorithmParameterException
        {
            AccessController.doPrivileged(new PrivilegedAction<Object>()
            {
                public Object run()
                {
                    TLSPRFKeyGenerator.this.spec = (TlsPrfParameterSpec)algorithmParameterSpec;
                    TLSPRFKeyGenerator.this.secureRandom = secureRandom;
                    return null;
                }
            });
        }

        @Override
        protected SecretKey engineGenerateKey()
        {
            return AccessController.doPrivileged(new PrivilegedAction<SecretKey>()
            {
                public SecretKey run()
                {
                    return calculatePRF(spec, "DUMMY");
                }
            });
        }
    }

    private static FipsKDF.TLSPRF getPRF(String alg)
    {
        if (alg.equals("NONE"))
        {
            return null;
        }
        if (alg.equals("SHA-256"))
        {
            return FipsKDF.TLSPRF.SHA256_HMAC;
        }
        if (alg.equals("SHA-384"))
        {
            return FipsKDF.TLSPRF.SHA384_HMAC;
        }
        if (alg.equals("SHA-512"))
        {
            return FipsKDF.TLSPRF.SHA512_HMAC;
        }

        throw new IllegalStateException("Unknown PRF: " + alg);
    }

    private static TlsPrfParameterSpec createPrfParameterSpec(
        SecretKey secret, String label, byte[] seed, int outputLength, String prfHashAlg, int prfHashLength, int prfBlockSize)
    {
        Object[] args;
        if (hasPrfMethods)
        {
            args = new Object[] {
                        secret, label, seed, outputLength, prfHashAlg, prfHashLength, prfBlockSize };
        }
        else
        {
            args = new Object[] {
                        secret, label, seed, outputLength };
        }

        try
        {
            return (TlsPrfParameterSpec)tlsPrfParameterSpecConstructor.newInstance(args);
        }
        catch (Exception e)
        {
            throw new IllegalStateException("Unable to construct TlsPrfParameterSpec: " + e.getMessage(), e);
        }
    }
}
