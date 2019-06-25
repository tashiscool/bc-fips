package org.bouncycastle.jcajce.provider;

import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;

import org.bouncycastle.asn1.iana.IANAObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.crypto.AuthenticationParameters;
import org.bouncycastle.crypto.SymmetricKeyGenerator;
import org.bouncycastle.crypto.fips.FipsSHS;

class ProvSHS
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
        private final FipsSHS.AuthParameters algorithm;

        ParametersCreator(FipsSHS.AuthParameters algorithm)
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
            if (spec != null)
            {
                throw new InvalidAlgorithmParameterException("Unknown AlgorithmParameterSpec found: " + spec.getClass().getName());
            }

            return getBaseParameters();
        }
    }

    private static class TruncatedParametersCreator
        implements MacParametersCreator
    {
        private final FipsSHS.AuthParameters algorithm;
        private final int macSizeInBits;

        TruncatedParametersCreator(FipsSHS.AuthParameters algorithm, int macSizeInBits)
        {
            this.algorithm = algorithm;
            this.macSizeInBits = macSizeInBits;
        }

        public AuthenticationParameters getBaseParameters()
        {
            return algorithm.withMACSize(macSizeInBits);
        }

        public AuthenticationParameters createParameters(boolean forEncryption, AlgorithmParameterSpec spec, SecureRandom random)
            throws InvalidAlgorithmParameterException
        {
            return getBaseParameters();
        }
    }

    static class SHA1
        extends DigestAlgorithmProvider
    {
        private static final String PREFIX = SHA1.class.getName();

        void configure(final BouncyCastleFipsProvider provider)
        {
            provider.addAlgorithmImplementation("MessageDigest.SHA-1", PREFIX + "$Digest", new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new BaseMessageDigest(FipsSHS.SHA1);
                }
            });
            provider.addAlias("MessageDigest", "SHA-1", "SHA1", "SHA");
            provider.addAlias("MessageDigest", "SHA-1", OIWObjectIdentifiers.idSHA1);

            addHMACAlgorithm(provider, "SHA-1",
                PREFIX + "$HashMac", new EngineCreator()
                {
                    public Object createInstance(Object constructorParameter)
                    {
                        return new BaseHMac(FipsSHS.Algorithm.SHA1_HMAC, new ParametersCreator(FipsSHS.SHA1_HMAC));
                    }
                },
                PREFIX + "$KeyGenerator", new EngineCreator()
                {
                    public Object createInstance(Object constructorParameter)
                    {
                        return new BaseKeyGenerator(provider, "HmacSHA1", 160, new KeyGeneratorCreator()
                        {
                            public SymmetricKeyGenerator createInstance(int keySize, SecureRandom random)
                            {
                                return new FipsSHS.KeyGenerator(FipsSHS.Algorithm.SHA1_HMAC, keySize, random);
                            }
                        });
                    }
                },
                PREFIX + "$SecretKeyFactory", new EngineCreator()
                {
                    public Object createInstance(Object constructorParameter)
                    {
                        return new BaseSecretKeyFactory("HmacSHA1", FipsSHS.Algorithm.SHA1_HMAC, anythingGoesValidator);
                    }
                }
            );

            addHMACAlias(provider, "SHA-1", "HMAC-SHA1", "HMACSHA1", "HMACSHA");
            addHMACAlias(provider, "SHA-1", PKCSObjectIdentifiers.id_hmacWithSHA1, IANAObjectIdentifiers.hmacSHA1, OIWObjectIdentifiers.idSHA1);

            provider.addAlgorithmImplementation("Mac.HMAC128SHA1", PREFIX + "$Hmac128", new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new BaseHMac(FipsSHS.Algorithm.SHA1_HMAC, new TruncatedParametersCreator(FipsSHS.SHA1_HMAC, 128));
                }
            });
            provider.addAlias("Mac", "HMAC128SHA1", "HMAC128SHA-1");
        }
    }

    static class SHA224
        extends DigestAlgorithmProvider
    {
        private static final String PREFIX = SHA224.class.getName();

        public void configure(final BouncyCastleFipsProvider provider)
        {
            provider.addAlgorithmImplementation("MessageDigest.SHA-224", PREFIX + "$Digest", new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new BaseMessageDigest(FipsSHS.SHA224);
                }
            });
            provider.addAlias("MessageDigest", "SHA-224", "SHA224");
            provider.addAlias("MessageDigest", "SHA-224", NISTObjectIdentifiers.id_sha224);

            addHMACAlgorithm(provider, "SHA-224",
                PREFIX + "$HashMac", new EngineCreator()
                {
                    public Object createInstance(Object constructorParameter)
                    {
                        return new BaseHMac(FipsSHS.Algorithm.SHA224_HMAC, new ParametersCreator(FipsSHS.SHA224_HMAC));
                    }
                },
                PREFIX + "$KeyGenerator", new EngineCreator()
                {

                    public Object createInstance(Object constructorParameter)
                    {
                        return new BaseKeyGenerator(provider, "HmacSHA224", 224, new KeyGeneratorCreator()
                        {
                            public SymmetricKeyGenerator createInstance(int keySize, SecureRandom random)
                            {
                                return new FipsSHS.KeyGenerator(FipsSHS.Algorithm.SHA224_HMAC, keySize, random);
                            }
                        });
                    }
                },
                PREFIX + "$SecretKeyFactory", new EngineCreator()
                {
                    public Object createInstance(Object constructorParameter)
                    {
                        return new BaseSecretKeyFactory("HmacSHA224", FipsSHS.Algorithm.SHA224_HMAC, anythingGoesValidator);
                    }
                }
            );

            addHMACAlias(provider, "SHA-224", "HMAC-SHA224", "HMACSHA224");
            addHMACAlias(provider, "SHA-224", PKCSObjectIdentifiers.id_hmacWithSHA224, NISTObjectIdentifiers.id_sha224);

            provider.addAlgorithmImplementation("Mac.HMAC128SHA224", PREFIX + "$Hmac128", new EngineCreator()
                        {
                            public Object createInstance(Object constructorParameter)
                            {
                                return new BaseHMac(FipsSHS.Algorithm.SHA224_HMAC, new TruncatedParametersCreator(FipsSHS.SHA224_HMAC, 128));
                            }
                        });
            provider.addAlias("Mac", "HMAC128SHA224", "HMAC128SHA-224");
        }
    }

    static class SHA256
        extends DigestAlgorithmProvider
    {
        private static final String PREFIX = SHA256.class.getName();

        public void configure(final BouncyCastleFipsProvider provider)
        {
            provider.addAlgorithmImplementation("MessageDigest.SHA-256", PREFIX + "$Digest", new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new BaseMessageDigest(FipsSHS.SHA256);
                }
            });
            provider.addAlias("MessageDigest", "SHA-256", "SHA256");
            provider.addAlias("MessageDigest", "SHA-256", NISTObjectIdentifiers.id_sha256);

            addHMACAlgorithm(provider, "SHA-256",
                PREFIX + "$HashMac", new EngineCreator()
                {
                    public Object createInstance(Object constructorParameter)
                    {
                        return new BaseHMac(FipsSHS.Algorithm.SHA256_HMAC, new ParametersCreator(FipsSHS.SHA256_HMAC));
                    }
                },
                PREFIX + "$KeyGenerator", new EngineCreator()
                {

                    public Object createInstance(Object constructorParameter)
                    {
                        return new BaseKeyGenerator(provider, "HmacSHA256", 256, new KeyGeneratorCreator()
                        {
                            public SymmetricKeyGenerator createInstance(int keySize, SecureRandom random)
                            {
                                return new FipsSHS.KeyGenerator(FipsSHS.Algorithm.SHA256_HMAC, keySize, random);
                            }
                        });
                    }
                },
                PREFIX + "$SecretKeyFactory", new EngineCreator()
                {
                    public Object createInstance(Object constructorParameter)
                    {
                        return new BaseSecretKeyFactory("HmacSHA256", FipsSHS.Algorithm.SHA256_HMAC, anythingGoesValidator);
                    }
                }
            );

            addHMACAlias(provider, "SHA-256", "HMAC-SHA256", "HMACSHA256");
            addHMACAlias(provider, "SHA-256", PKCSObjectIdentifiers.id_hmacWithSHA256, NISTObjectIdentifiers.id_sha256);

            provider.addAlgorithmImplementation("Mac.HMAC128SHA256", PREFIX + "$Hmac128", new EngineCreator()
                        {
                            public Object createInstance(Object constructorParameter)
                            {
                                return new BaseHMac(FipsSHS.Algorithm.SHA256_HMAC, new TruncatedParametersCreator(FipsSHS.SHA256_HMAC, 128));
                            }
                        });
            provider.addAlias("Mac", "HMAC128SHA256", "HMAC128SHA-256");
        }
    }

    static class SHA384
        extends DigestAlgorithmProvider
    {
        private static final String PREFIX = SHA384.class.getName();

        public void configure(final BouncyCastleFipsProvider provider)
        {
            provider.addAlgorithmImplementation("MessageDigest.SHA-384", PREFIX + "$Digest", new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new BaseMessageDigest(FipsSHS.SHA384);
                }
            });
            provider.addAlias("MessageDigest", "SHA-384", "SHA384");
            provider.addAlias("MessageDigest", "SHA-384", NISTObjectIdentifiers.id_sha384);

            addHMACAlgorithm(provider, "SHA-384",
                PREFIX + "$HashMac", new EngineCreator()
                {
                    public Object createInstance(Object constructorParameter)
                    {
                        return new BaseHMac(FipsSHS.Algorithm.SHA384_HMAC, new ParametersCreator(FipsSHS.SHA384_HMAC));
                    }
                },
                PREFIX + "$KeyGenerator", new EngineCreator()
                {

                    public Object createInstance(Object constructorParameter)
                    {
                        return new BaseKeyGenerator(provider, "HmacSHA384", 384, new KeyGeneratorCreator()
                        {
                            public SymmetricKeyGenerator createInstance(int keySize, SecureRandom random)
                            {
                                return new FipsSHS.KeyGenerator(FipsSHS.Algorithm.SHA384_HMAC, keySize, random);
                            }
                        });
                    }
                },
                PREFIX + "$SecretKeyFactory", new EngineCreator()
                {
                    public Object createInstance(Object constructorParameter)
                    {
                        return new BaseSecretKeyFactory("HmacSHA384", FipsSHS.Algorithm.SHA384_HMAC, anythingGoesValidator);
                    }
                }
            );

            addHMACAlias(provider, "SHA-384", "HMAC-SHA384", "HMACSHA384");
            addHMACAlias(provider, "SHA-384", PKCSObjectIdentifiers.id_hmacWithSHA384, NISTObjectIdentifiers.id_sha384);

            provider.addAlgorithmImplementation("Mac.HMAC256SHA384", PREFIX + "$Hmac256", new EngineCreator()
                        {
                            public Object createInstance(Object constructorParameter)
                            {
                                return new BaseHMac(FipsSHS.Algorithm.SHA384_HMAC, new TruncatedParametersCreator(FipsSHS.SHA384_HMAC, 256));
                            }
                        });
            provider.addAlias("Mac", "HMAC256SHA384", "HMAC256SHA-384");
        }
    }

    public static class SHA512
        extends DigestAlgorithmProvider
    {
        private static final String PREFIX = SHA512.class.getName();

        public void configure(final BouncyCastleFipsProvider provider)
        {
            provider.addAlgorithmImplementation("MessageDigest.SHA-512", PREFIX + "$Digest", new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new BaseMessageDigest(FipsSHS.SHA512);
                }
            });
            provider.addAlias("MessageDigest", "SHA-512", "SHA512");
            provider.addAlias("MessageDigest", "SHA-512", NISTObjectIdentifiers.id_sha512);

            addHMACAlgorithm(provider, "SHA-512",
                PREFIX + "$HashMac", new EngineCreator()
                {
                    public Object createInstance(Object constructorParameter)
                    {
                        return new BaseHMac(FipsSHS.Algorithm.SHA512_HMAC, new ParametersCreator(FipsSHS.SHA512_HMAC));
                    }
                },
                PREFIX + "$KeyGenerator", new EngineCreator()
                {

                    public Object createInstance(Object constructorParameter)
                    {
                        return new BaseKeyGenerator(provider, "HmacSHA512", 512, new KeyGeneratorCreator()
                        {
                            public SymmetricKeyGenerator createInstance(int keySize, SecureRandom random)
                            {
                                return new FipsSHS.KeyGenerator(FipsSHS.Algorithm.SHA512_HMAC, keySize, random);
                            }
                        });
                    }
                },
                PREFIX + "$SecretKeyFactory", new EngineCreator()
                {
                    public Object createInstance(Object constructorParameter)
                    {
                        return new BaseSecretKeyFactory("HmacSHA512", FipsSHS.Algorithm.SHA512_HMAC, anythingGoesValidator);
                    }
                }
            );

            addHMACAlias(provider, "SHA-512", "HMAC-SHA512", "HMACSHA512");
            addHMACAlias(provider, "SHA-512", PKCSObjectIdentifiers.id_hmacWithSHA512, NISTObjectIdentifiers.id_sha512);

            provider.addAlgorithmImplementation("Mac.HMAC256SHA512", PREFIX + "$HashMac256", new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new BaseHMac(FipsSHS.Algorithm.SHA512_HMAC, new TruncatedParametersCreator(FipsSHS.SHA512_HMAC, 256));
                }
            });
            provider.addAlias("Mac", "HMAC256SHA512", "HMAC256SHA-512");

            provider.addAlgorithmImplementation("MessageDigest.SHA-512(224)", PREFIX + "$DigestT224", new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new BaseMessageDigest(FipsSHS.SHA512_224);
                }
            });
            provider.addAlias("MessageDigest", "SHA-512(224)", "SHA512(224)", "SHA-512/224", "SHA512/224");
            provider.addAlias("MessageDigest", "SHA-512(224)", NISTObjectIdentifiers.id_sha512_224);

            provider.addAlgorithmImplementation("MessageDigest.SHA-512(256)", PREFIX + "$DigestT256", new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new BaseMessageDigest(FipsSHS.SHA512_256);
                }
            });
            provider.addAlias("MessageDigest", "SHA-512(256)", "SHA512(256)", "SHA-512/256", "SHA512/256");
            provider.addAlias("MessageDigest", "SHA-512(256)", NISTObjectIdentifiers.id_sha512_256);

            addHMACAlgorithm(provider, "SHA-512(224)", PREFIX + "$HashMacT224", new EngineCreator()
                {
                    public Object createInstance(Object constructorParameter)
                    {
                        return new BaseHMac(FipsSHS.Algorithm.SHA512_224_HMAC, new ParametersCreator(FipsSHS.SHA512_224_HMAC));
                    }
                },
                PREFIX + "$KeyGeneratorT224", new EngineCreator()
                {
                    public Object createInstance(Object constructorParameter)
                    {
                        return new BaseKeyGenerator(provider, "HmacSHA512(224)", 224, new KeyGeneratorCreator()
                        {
                            public SymmetricKeyGenerator createInstance(int keySize, SecureRandom random)
                            {
                                return new FipsSHS.KeyGenerator(FipsSHS.Algorithm.SHA512_224_HMAC, keySize, random);
                            }
                        });
                    }
                },
                PREFIX + "$SecretKeyFactoryT224", new EngineCreator()
                {
                    public Object createInstance(Object constructorParameter)
                    {
                        return new BaseSecretKeyFactory("HmacSHA512(224)", FipsSHS.Algorithm.SHA512_224_HMAC, anythingGoesValidator);
                    }
                });
            addHMACAlias(provider, "SHA-512(224)", "HMAC-SHA512(224)", "HMACSHA512(224)", "HMAC-SHA512/224", "HMACSHA512/224");

            provider.addAlgorithmImplementation("Mac.HMAC128SHA512(224)", PREFIX + "$Hmac128_224", new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new BaseHMac(FipsSHS.Algorithm.SHA512_224_HMAC, new TruncatedParametersCreator(FipsSHS.SHA512_224_HMAC, 128));
                }
            });
            provider.addAlias("Mac", "HMAC128SHA512(224)", "HMAC128SHA-512(224)");

            addHMACAlgorithm(provider, "SHA-512(256)", PREFIX + "$HashMacT256", new EngineCreator()
                {
                    public Object createInstance(Object constructorParameter)
                    {
                        return new BaseHMac(FipsSHS.Algorithm.SHA512_256_HMAC, new ParametersCreator(FipsSHS.SHA512_256_HMAC));
                    }
                }, PREFIX + "$KeyGeneratorT256", new EngineCreator()
                {
                    public Object createInstance(Object constructorParameter)
                    {
                        return new BaseKeyGenerator(provider, "HmacSHA512(256)", 256, new KeyGeneratorCreator()
                        {
                            public SymmetricKeyGenerator createInstance(int keySize, SecureRandom random)
                            {
                                return new FipsSHS.KeyGenerator(FipsSHS.Algorithm.SHA512_256_HMAC, keySize, random);
                            }
                        });
                    }
                },
                PREFIX + "$SecretKeyFactoryT256", new EngineCreator()
                {
                    public Object createInstance(Object constructorParameter)
                    {
                        return new BaseSecretKeyFactory("HmacSHA512(256)", FipsSHS.Algorithm.SHA512_256_HMAC, anythingGoesValidator);
                    }
                });
            addHMACAlias(provider, "SHA-512(256)", "HMAC-SHA512(256)", "HMACSHA512(256)", "HMAC-SHA512/256", "HMACSHA512/256");

            provider.addAlgorithmImplementation("Mac.HMAC128SHA512(256)", PREFIX + "$Hmac128_256", new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new BaseHMac(FipsSHS.Algorithm.SHA512_256_HMAC, new TruncatedParametersCreator(FipsSHS.SHA512_256_HMAC, 128));
                }
            });
            provider.addAlias("Mac", "HMAC128SHA512(256)", "HMAC128SHA-512(256)");
        }
    }

    static class SHA3_224
        extends DigestAlgorithmProvider
    {
        private static final String PREFIX = SHA3_224.class.getName();

        public void configure(final BouncyCastleFipsProvider provider)
        {
            provider.addAlgorithmImplementation("MessageDigest.SHA3-224", PREFIX + "$Digest", new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new BaseMessageDigest(FipsSHS.SHA3_224);
                }
            });
            provider.addAlias("MessageDigest", "SHA3-224", NISTObjectIdentifiers.id_sha3_224);
        }
    }

    static class SHA3_256
        extends DigestAlgorithmProvider
    {
        private static final String PREFIX = SHA3_256.class.getName();

        public void configure(final BouncyCastleFipsProvider provider)
        {
            provider.addAlgorithmImplementation("MessageDigest.SHA3-256", PREFIX + "$Digest", new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new BaseMessageDigest(FipsSHS.SHA3_256);
                }
            });
            provider.addAlias("MessageDigest", "SHA3-256", NISTObjectIdentifiers.id_sha3_256);
        }
    }

    static class SHA3_384
        extends DigestAlgorithmProvider
    {
        private static final String PREFIX = SHA3_384.class.getName();

        public void configure(final BouncyCastleFipsProvider provider)
        {
            provider.addAlgorithmImplementation("MessageDigest.SHA3-384", PREFIX + "$Digest", new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new BaseMessageDigest(FipsSHS.SHA3_384);
                }
            });
            provider.addAlias("MessageDigest", "SHA3-384", NISTObjectIdentifiers.id_sha3_384);
        }
    }

    static class SHA3_512
        extends DigestAlgorithmProvider
    {
        private static final String PREFIX = SHA3_512.class.getName();

        public void configure(final BouncyCastleFipsProvider provider)
        {
            provider.addAlgorithmImplementation("MessageDigest.SHA3-512", PREFIX + "$Digest", new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new BaseMessageDigest(FipsSHS.SHA3_512);
                }
            });
            provider.addAlias("MessageDigest", "SHA3-512", NISTObjectIdentifiers.id_sha3_512);
        }
    }
}
