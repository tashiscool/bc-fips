package org.bouncycastle.jcajce.provider;

import java.security.InvalidAlgorithmParameterException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;

import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.gnu.GNUObjectIdentifiers;
import org.bouncycastle.asn1.iana.IANAObjectIdentifiers;
import org.bouncycastle.asn1.iso.ISOIECObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.crypto.AuthenticationParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.DigestOperatorFactory;
import org.bouncycastle.crypto.OutputDigestCalculator;
import org.bouncycastle.crypto.Parameters;
import org.bouncycastle.crypto.SymmetricKeyGenerator;
import org.bouncycastle.crypto.UpdateOutputStream;
import org.bouncycastle.crypto.fips.FipsDigestOperatorFactory;
import org.bouncycastle.crypto.fips.FipsSHS;
import org.bouncycastle.crypto.general.GeneralParameters;
import org.bouncycastle.crypto.general.SecureHash;
import org.bouncycastle.crypto.internal.Digest;

class ProvSecureHash
{
    private static final BaseSecretKeyFactory.Validator anythingGoesValidator = new BaseSecretKeyFactory.Validator()
    {
        public byte[] validated(byte[] keyBytes)
            throws InvalidKeySpecException
        {
            return keyBytes;
        }
    };

    private static class ParametersCreator
        implements MacParametersCreator
    {
        private final SecureHash.AuthParameters algorithm;

        ParametersCreator(SecureHash.AuthParameters algorithm)
        {
            this.algorithm = algorithm;
        }

        public AuthenticationParameters getBaseParameters()
        {
            return algorithm;
        }

        public AuthenticationParameters createParameters(boolean forEncryption, AlgorithmParameterSpec spec, SecureRandom random)
            throws InvalidAlgorithmParameterException
        {
            return algorithm;
        }
    }

    private static DigestOperatorFactory<GeneralParameters> generalOperatorFactory;

    private static BaseMessageDigest getDigestImplementation(SecureHash.Parameters algorithm)
    {
        if (CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            return null;
        }

        if (generalOperatorFactory == null)
        {
            generalOperatorFactory = new SecureHash.OperatorFactory();
        }

        return new BaseMessageDigest(generalOperatorFactory.createOutputDigestCalculator(algorithm));
    }

    static class GOST3411
        extends DigestAlgorithmProvider
    {
        private static final String PREFIX = GOST3411.class.getName();

        public void configure(final BouncyCastleFipsProvider provider)
        {
            provider.addAlgorithmImplementation("MessageDigest.GOST3411", PREFIX + "$Digest", new GuardedEngineCreator(new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return getDigestImplementation(SecureHash.GOST3411);
                }
            }));

            provider.addAlias("MessageDigest", "GOST3411", "GOST", "GOST-3411");
            provider.addAlias("MessageDigest", "GOST3411", CryptoProObjectIdentifiers.gostR3411);

            addHMACAlgorithm(provider, "GOST3411", PREFIX + "$HashMac", new GuardedEngineCreator(new EngineCreator()
            {
                    public Object createInstance(Object constructorParameter)
                    {
                        return new BaseHMac(SecureHash.Algorithm.GOST3411_HMAC, new ParametersCreator(SecureHash.GOST3411_HMAC));
                    }
                }),
                PREFIX + "$KeyGenerator", new GuardedEngineCreator(new EngineCreator()
                {
                    public Object createInstance(Object constructorParameter)
                    {
                        return new BaseKeyGenerator(provider, "HmacGOST3411", 256, new KeyGeneratorCreator()
                        {
                            public SymmetricKeyGenerator createInstance(int keySize, SecureRandom random)
                            {
                                return new SecureHash.KeyGenerator(SecureHash.Algorithm.GOST3411_HMAC, keySize, random);
                            }
                        });
                    }
                }),
                PREFIX + "$SecretKeyFactory", new GuardedEngineCreator(new EngineCreator()
                {
                    public Object createInstance(Object constructorParameter)
                    {
                        return new BaseSecretKeyFactory("HmacGOST3411", SecureHash.Algorithm.GOST3411_HMAC, anythingGoesValidator);
                    }
                }));
            addHMACAlias(provider, "GOST3411", CryptoProObjectIdentifiers.gostR3411Hmac, CryptoProObjectIdentifiers.gostR3411);
        }
    }

    static class MD5
        extends DigestAlgorithmProvider
    {
        private static final String PREFIX = MD5.class.getName();

        public void configure(final BouncyCastleFipsProvider provider)
        {
            // special case due to TLS 1.1
            provider.addAlgorithmImplementation("MessageDigest.MD5", PREFIX + "$Digest", new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new MD5MessageDigest();
                }
            });
            provider.addAlias("MessageDigest", "MD5", PKCSObjectIdentifiers.md5);

            if (!CryptoServicesRegistrar.isInApprovedOnlyMode())
            {
                addHMACAlgorithm(provider, "MD5", PREFIX + "$HashMac", new GuardedEngineCreator(new EngineCreator()
                    {
                        public Object createInstance(Object constructorParameter)
                        {
                            return new BaseHMac(SecureHash.Algorithm.MD5_HMAC, new ParametersCreator(SecureHash.MD5_HMAC));
                        }
                    }), PREFIX + "$KeyGenerator", new GuardedEngineCreator(new EngineCreator()
                    {
                        public Object createInstance(Object constructorParameter)
                        {
                            return new BaseKeyGenerator(provider, "HmacMD5", 128, new KeyGeneratorCreator()
                            {
                                public SymmetricKeyGenerator createInstance(int keySize, SecureRandom random)
                                {
                                    return new SecureHash.KeyGenerator(SecureHash.Algorithm.MD5_HMAC, keySize, random);
                                }
                            });
                        }
                    }),
                    PREFIX + "$SecretKeyFactory", new GuardedEngineCreator(new EngineCreator()
                    {
                        public Object createInstance(Object constructorParameter)
                        {
                            return new BaseSecretKeyFactory("HmacMD5", SecureHash.Algorithm.MD5_HMAC, anythingGoesValidator);
                        }
                    }));
                addHMACAlias(provider, "MD5", IANAObjectIdentifiers.hmacMD5);
            }
        }
    }

    public static class RIPEMD128
        extends DigestAlgorithmProvider
    {
        private static final String PREFIX = RIPEMD128.class.getName();

        public void configure(final BouncyCastleFipsProvider provider)
        {
            provider.addAlgorithmImplementation("MessageDigest.RIPEMD128", PREFIX + "$Digest", new GuardedEngineCreator(new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return getDigestImplementation(SecureHash.RIPEMD128);
                }
            }));

            provider.addAlias("MessageDigest", "RIPEMD128", "RIPEMD-128");
            provider.addAlias("MessageDigest", "RIPEMD128", TeleTrusTObjectIdentifiers.ripemd128, ISOIECObjectIdentifiers.ripemd128);

            addHMACAlgorithm(provider, "RIPEMD128", PREFIX + "$HashMac", new GuardedEngineCreator(new EngineCreator()
                {
                    public Object createInstance(Object constructorParameter)
                    {
                        return new BaseHMac(SecureHash.Algorithm.RIPEMD128_HMAC, new ParametersCreator(SecureHash.RIPEMD128_HMAC));
                    }
                }), PREFIX + "$KeyGenerator", new GuardedEngineCreator(new EngineCreator()
                {
                    public Object createInstance(Object constructorParameter)
                    {
                        return new BaseKeyGenerator(provider, "HmacRIPEMD128", 128, new KeyGeneratorCreator()
                        {
                            public SymmetricKeyGenerator createInstance(int keySize, SecureRandom random)
                            {
                                return new SecureHash.KeyGenerator(SecureHash.Algorithm.RIPEMD128_HMAC, keySize, random);
                            }
                        });
                    }
                }),
                PREFIX + "$SecretKeyFactory", new GuardedEngineCreator(new EngineCreator()
                {
                    public Object createInstance(Object constructorParameter)
                    {
                        return new BaseSecretKeyFactory("HmacRIPEMD128", SecureHash.Algorithm.RIPEMD128_HMAC, anythingGoesValidator);
                    }
                }));
        }
    }

    public static class RIPEMD160
        extends DigestAlgorithmProvider
    {
        private static final String PREFIX = RIPEMD160.class.getName();

        public void configure(final BouncyCastleFipsProvider provider)
        {
            provider.addAlgorithmImplementation("MessageDigest.RIPEMD160", PREFIX + "$Digest", new GuardedEngineCreator(new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return getDigestImplementation(SecureHash.RIPEMD160);
                }
            }));
            provider.addAlias("MessageDigest", "RIPEMD160", "RIPEMD-160");
            provider.addAlias("MessageDigest", "RIPEMD160", TeleTrusTObjectIdentifiers.ripemd160, ISOIECObjectIdentifiers.ripemd160);

            addHMACAlgorithm(provider, "RIPEMD160", PREFIX + "$HashMac", new GuardedEngineCreator(new EngineCreator()
                {
                    public Object createInstance(Object constructorParameter)
                    {
                        return new BaseHMac(SecureHash.Algorithm.RIPEMD160_HMAC, new ParametersCreator(SecureHash.RIPEMD160_HMAC));
                    }
                }), PREFIX + "$KeyGenerator", new GuardedEngineCreator(new EngineCreator()
                {
                    public Object createInstance(Object constructorParameter)
                    {
                        return new BaseKeyGenerator(provider, "HmacRIPEMD160", 160, new KeyGeneratorCreator()
                        {
                            public SymmetricKeyGenerator createInstance(int keySize, SecureRandom random)
                            {
                                return new SecureHash.KeyGenerator(SecureHash.Algorithm.RIPEMD160_HMAC, keySize, random);
                            }
                        });
                    }
                }),
                PREFIX + "$SecretKeyFactory", new GuardedEngineCreator(new EngineCreator()
                {
                    public Object createInstance(Object constructorParameter)
                    {
                        return new BaseSecretKeyFactory("HmacRIPEMD160", SecureHash.Algorithm.RIPEMD160_HMAC, anythingGoesValidator);
                    }
                }));
            addHMACAlias(provider, "RIPEMD160", IANAObjectIdentifiers.hmacRIPEMD160);
        }
    }

    public static class RIPEMD256
        extends DigestAlgorithmProvider
    {
        private static final String PREFIX = RIPEMD256.class.getName();

        public void configure(final BouncyCastleFipsProvider provider)
        {
            provider.addAlgorithmImplementation("MessageDigest.RIPEMD256", PREFIX + "$Digest", new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return getDigestImplementation(SecureHash.RIPEMD256);
                }
            });
            provider.addAlias("MessageDigest", "RIPEMD256", "RIPEMD-256");
            provider.addAlias("MessageDigest", "RIPEMD256", TeleTrusTObjectIdentifiers.ripemd256);

            addHMACAlgorithm(provider, "RIPEMD256", PREFIX + "$HashMac", new GuardedEngineCreator(new EngineCreator()
                {
                    public Object createInstance(Object constructorParameter)
                    {
                        return new BaseHMac(SecureHash.Algorithm.RIPEMD256_HMAC, new ParametersCreator(SecureHash.RIPEMD256_HMAC));
                    }
                }), PREFIX + "$KeyGenerator", new GuardedEngineCreator(new EngineCreator()
                {
                    public Object createInstance(Object constructorParameter)
                    {
                        return new BaseKeyGenerator(provider, "HmacRIPEMD256", 256, new KeyGeneratorCreator()
                        {
                            public SymmetricKeyGenerator createInstance(int keySize, SecureRandom random)
                            {
                                return new SecureHash.KeyGenerator(SecureHash.Algorithm.RIPEMD256_HMAC, keySize, random);
                            }
                        });
                    }
                }),
                PREFIX + "$SecretKeyFactory", new GuardedEngineCreator(new EngineCreator()
                {
                    public Object createInstance(Object constructorParameter)
                    {
                        return new BaseSecretKeyFactory("HmacRIPEMD256", SecureHash.Algorithm.RIPEMD256_HMAC, anythingGoesValidator);
                    }
                }));
        }
    }

    static class RIPEMD320
        extends DigestAlgorithmProvider
    {
        private static final String PREFIX = RIPEMD320.class.getName();

        public void configure(final BouncyCastleFipsProvider provider)
        {
            provider.addAlgorithmImplementation("MessageDigest.RIPEMD320", PREFIX + "$Digest", new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return getDigestImplementation(SecureHash.RIPEMD320);
                }
            });
            provider.addAlias("MessageDigest", "RIPEMD320", "RIPEMD-320");

            addHMACAlgorithm(provider, "RIPEMD320", PREFIX + "$HashMac", new GuardedEngineCreator(new EngineCreator()
                {
                    public Object createInstance(Object constructorParameter)
                    {
                        return new BaseHMac(SecureHash.Algorithm.RIPEMD320_HMAC, new ParametersCreator(SecureHash.RIPEMD320_HMAC));
                    }
                }), PREFIX + "$KeyGenerator", new GuardedEngineCreator(new EngineCreator()
                {
                    public Object createInstance(Object constructorParameter)
                    {
                        return new BaseKeyGenerator(provider, "HmacRIPEMD320", 320, new KeyGeneratorCreator()
                        {
                            public SymmetricKeyGenerator createInstance(int keySize, SecureRandom random)
                            {
                                return new SecureHash.KeyGenerator(SecureHash.Algorithm.RIPEMD320_HMAC, keySize, random);
                            }
                        });
                    }
                }),
                PREFIX + "$SecretKeyFactory", new GuardedEngineCreator(new EngineCreator()
                {
                    public Object createInstance(Object constructorParameter)
                    {
                        return new BaseSecretKeyFactory("HmacRIPEMD320", SecureHash.Algorithm.RIPEMD320_HMAC, anythingGoesValidator);
                    }
                }));
        }
    }

    static class Tiger
        extends DigestAlgorithmProvider
    {
        private static final String PREFIX = Tiger.class.getName();

        public void configure(final BouncyCastleFipsProvider provider)
        {
            provider.addAlgorithmImplementation("MessageDigest.TIGER", PREFIX + "$Digest", new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return getDigestImplementation(SecureHash.TIGER);
                }
            });
            provider.addAlias("MessageDigest", "TIGER", GNUObjectIdentifiers.Tiger_192);

            addHMACAlgorithm(provider, "TIGER",
                PREFIX + "$HashMac", new GuardedEngineCreator(new EngineCreator()
                {
                    public Object createInstance(Object constructorParameter)
                    {
                        return new BaseHMac(SecureHash.Algorithm.TIGER_HMAC, new ParametersCreator(SecureHash.TIGER_HMAC));
                    }
                }),
                PREFIX + "$KeyGenerator", new GuardedEngineCreator(new EngineCreator()
                {
                    public Object createInstance(Object constructorParameter)
                    {
                        return new BaseKeyGenerator(provider, "HmacTiger", 192, new KeyGeneratorCreator()
                        {
                            public SymmetricKeyGenerator createInstance(int keySize, SecureRandom random)
                            {
                                return new SecureHash.KeyGenerator(SecureHash.Algorithm.TIGER_HMAC, keySize, random);
                            }
                        });
                    }
                }
                ),
                PREFIX + "$SecretKeyFactory", new GuardedEngineCreator(new EngineCreator()
                {
                    public Object createInstance(Object constructorParameter)
                    {
                        return new BaseSecretKeyFactory("HmacTiger", SecureHash.Algorithm.TIGER_HMAC, anythingGoesValidator);
                    }
                }));
            addHMACAlias(provider, "TIGER", IANAObjectIdentifiers.hmacTIGER);
        }
    }

    static class Whirlpool
        extends DigestAlgorithmProvider
    {
        private static final String PREFIX = Whirlpool.class.getName();

        public void configure(final BouncyCastleFipsProvider provider)
        {
            provider.addAlgorithmImplementation("MessageDigest.WHIRLPOOL", PREFIX + "$Digest", new GuardedEngineCreator(new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return getDigestImplementation(SecureHash.WHIRLPOOL);
                }
            }));
            provider.addAlias("MessageDigest", "WHIRLPOOL", ISOIECObjectIdentifiers.whirlpool);

            addHMACAlgorithm(provider, "WHIRLPOOL", PREFIX + "$HashMac", new GuardedEngineCreator(new EngineCreator()
                {
                    public Object createInstance(Object constructorParameter)
                    {
                        return new BaseHMac(SecureHash.Algorithm.WHIRLPOOL_HMAC, new ParametersCreator(SecureHash.WHIRLPOOL_HMAC));
                    }
                }), PREFIX + "$KeyGenerator", new GuardedEngineCreator(new EngineCreator()
                {
                    public Object createInstance(Object constructorParameter)
                    {
                        return new BaseKeyGenerator(provider, "HmacWhirlpool", 512, new KeyGeneratorCreator()
                        {
                            public SymmetricKeyGenerator createInstance(int keySize, SecureRandom random)
                            {
                                return new SecureHash.KeyGenerator(SecureHash.Algorithm.WHIRLPOOL_HMAC, keySize, random);
                            }
                        });
                    }
                }),
                PREFIX + "$SecretKeyFactory", new GuardedEngineCreator(new EngineCreator()
                {
                    public Object createInstance(Object constructorParameter)
                    {
                        return new BaseSecretKeyFactory("HmacWhirlpool", SecureHash.Algorithm.WHIRLPOOL_HMAC, anythingGoesValidator);
                    }
                }));
        }
    }

    // MD5 is a special case due to TLS.
    private static class MD5MessageDigest
        extends MessageDigest
        implements Cloneable
    {
        private final MD5Digest baseDigest;

        protected MD5MessageDigest()
        {
            super("MD5");
            baseDigest = new MD5Digest();
        }

        protected MD5MessageDigest(MD5Digest md5Digest)
        {
            super("MD5");
            baseDigest = new MD5Digest(md5Digest);
        }

        protected void engineReset()
        {
            baseDigest.reset();
        }

        protected void engineUpdate(
            byte    input)
        {
            baseDigest.update(input);
        }

        protected void engineUpdate(
            byte[]  input,
            int     offset,
            int     len)
        {
            baseDigest.update(input, offset, len);
        }

        protected byte[] engineDigest()
        {
            byte[]  digestBytes = new byte[baseDigest.getDigestSize()];

            baseDigest.doFinal(digestBytes, 0);

            engineReset();

            return digestBytes;
        }

        protected int engineGetDigestLength()
        {
            return baseDigest.getDigestSize();
        }

        public Object clone()
            throws CloneNotSupportedException
        {
            return new MD5MessageDigest(baseDigest);
        }
    }
}
