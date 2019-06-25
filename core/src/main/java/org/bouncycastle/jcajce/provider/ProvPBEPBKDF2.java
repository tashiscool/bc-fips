package org.bouncycastle.jcajce.provider;

import java.io.IOException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.KeySpec;

import javax.crypto.SecretKey;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PBKDF2Params;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.DigestAlgorithm;
import org.bouncycastle.crypto.PasswordBasedDeriver;
import org.bouncycastle.crypto.PasswordConverter;
import org.bouncycastle.crypto.fips.FipsAlgorithm;
import org.bouncycastle.crypto.fips.FipsDigestAlgorithm;
import org.bouncycastle.crypto.fips.FipsPBKD;
import org.bouncycastle.crypto.fips.FipsSHS;
import org.bouncycastle.crypto.general.PBKD;
import org.bouncycastle.crypto.general.SecureHash;
import org.bouncycastle.jcajce.spec.PBKDF2KeySpec;
import org.bouncycastle.jcajce.spec.PBKDF2ParameterSpec;

class ProvPBEPBKDF2
    extends AlgorithmProvider
{
    private static final String PREFIX = ProvPBEPBKDF2.class.getName();

    public void configure(BouncyCastleFipsProvider provider)
    {
        provider.addAlgorithmImplementation("AlgorithmParameters.PBKDF2", PREFIX + "$AlgParams", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new AlgParams();
            }
        });
        provider.addAlias("AlgorithmParameters", "PBKDF2", "PBKDF2WITHUTF8", "PBKDF2WITHASCII", "PBKDF2WITH8BIT");
        provider.addAlias("AlgorithmParameters", "PBKDF2", PKCSObjectIdentifiers.id_PBKDF2);

        provider.addAlgorithmImplementation("SecretKeyFactory.PBKDF2", PREFIX + "$PBKDF2withUTF8", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BasePBKDF2("PBKDF2withHmacSHA1andUTF8", PasswordConverter.UTF8);
            }
        });

        provider.addAlias("SecretKeyFactory", "PBKDF2", "PBKDF2WITHUTF8");
        provider.addAlias("SecretKeyFactory", "PBKDF2", PKCSObjectIdentifiers.id_PBKDF2);

        provider.addAlgorithmImplementation("SecretKeyFactory.PBKDF2WITHHMACSHA1", PREFIX + "$PBKDF2withHMACSHA1andUTF8", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BasePBKDF2("PBKDF2withHmacSHA1andUTF8", PasswordConverter.UTF8, FipsSHS.Algorithm.SHA1_HMAC);
            }
        });
        provider.addAlgorithmImplementation("SecretKeyFactory.PBKDF2WITHHMACSHA224", PREFIX + "$PBKDF2withHMACSHA224andUTF8", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BasePBKDF2("PBKDF2withHmacSHA224andUTF8", PasswordConverter.UTF8, FipsSHS.Algorithm.SHA224_HMAC);
            }
        });
        provider.addAlgorithmImplementation("SecretKeyFactory.PBKDF2WITHHMACSHA256", PREFIX + "$PBKDF2withHMACSHA256andUTF8", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BasePBKDF2("PBKDF2withHmacSHA256andUTF8", PasswordConverter.UTF8, FipsSHS.Algorithm.SHA256_HMAC);
            }
        });
        provider.addAlgorithmImplementation("SecretKeyFactory.PBKDF2WITHHMACSHA384", PREFIX + "$PBKDF2withHMACSHA384andUTF8", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BasePBKDF2("PBKDF2withHmacSHA384andUTF8", PasswordConverter.UTF8, FipsSHS.Algorithm.SHA384_HMAC);
            }
        });
        provider.addAlgorithmImplementation("SecretKeyFactory.PBKDF2WITHHMACSHA512", PREFIX + "$PBKDF2withHMACSHA512andUTF8", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BasePBKDF2("PBKDF2withHmacSHA512andUTF8", PasswordConverter.UTF8, FipsSHS.Algorithm.SHA512_HMAC);
            }
        });

        if (!CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            provider.addAlgorithmImplementation("SecretKeyFactory.PBKDF2WITHHMACGOST3411", PREFIX + "$PBKDF2withHMACGOST3411andUTF8", new GuardedEngineCreator(new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new BasePBKDF2("PBKDF2withHmacGOST3411andUTF8", PasswordConverter.UTF8, SecureHash.Algorithm.GOST3411_HMAC);
                }
            }));
        }

        provider.addAlgorithmImplementation("SecretKeyFactory.PBKDF2WITHASCII", PREFIX + "$PBKDF2withASCII", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BasePBKDF2("PBKDF2withHmacSHA1and8BIT", PasswordConverter.ASCII);
            }
        });
        provider.addAlias("SecretKeyFactory", "PBKDF2WITHASCII", "PBKDF2WITH8BIT");
    }

    public static class AlgParams
        extends BaseAlgorithmParameters
    {
        PBKDF2Params params;

        protected byte[] localGetEncoded()
            throws IOException
        {
            return params.getEncoded(ASN1Encoding.DER);
        }

        protected AlgorithmParameterSpec localEngineGetParameterSpec(
            Class paramSpec)
            throws InvalidParameterSpecException
        {
            if (paramSpec == PBEParameterSpec.class)
            {
                return new PBEParameterSpec(params.getSalt(),
                    params.getIterationCount().intValue());
            }
            else if (paramSpec == PBKDF2ParameterSpec.class || paramSpec == AlgorithmParameterSpec.class)
            {
                int keySize = (params.getKeyLength() != null) ? params.getKeyLength().intValue() * 8 : 0;
                if (params.isDefaultPrf())
                {
                    return new PBKDF2ParameterSpec(params.getSalt(), params.getIterationCount().intValue(), keySize);
                }
                else
                {
                    return new PBKDF2ParameterSpec(params.getSalt(), params.getIterationCount().intValue(), keySize, params.getPrf());
                }
            }

            throw new InvalidParameterSpecException("AlgorithmParameterSpec not recognized: " + paramSpec.getName());
        }

        protected void engineInit(
            AlgorithmParameterSpec paramSpec)
            throws InvalidParameterSpecException
        {
            if (!(paramSpec instanceof PBEParameterSpec))
            {
                throw new InvalidParameterSpecException("PBEParameterSpec required to initialise a PBKDF2 PBE parameters algorithm parameters object");
            }

            if (paramSpec instanceof PBKDF2ParameterSpec)
            {
                PBKDF2ParameterSpec pbeSpec = (PBKDF2ParameterSpec)paramSpec;

                this.params = new PBKDF2Params(pbeSpec.getSalt(), pbeSpec.getIterationCount(), pbeSpec.getKeySize() / 8, pbeSpec.getPrf());
            }
            else
            {
                PBEParameterSpec pbeSpec = (PBEParameterSpec)paramSpec;

                this.params = new PBKDF2Params(pbeSpec.getSalt(), pbeSpec.getIterationCount());
            }
        }

        protected void localInit(
            byte[] params)
            throws IOException
        {
            this.params = PBKDF2Params.getInstance(ASN1Primitive.fromByteArray(params));
        }

        protected String engineToString()
        {
            return "PBKDF2 Parameters";
        }
    }

    public static class BasePBKDF2
        extends BaseKDFSecretKeyFactory
    {
        private final String algName;
        private final PasswordConverter passwordConverter;
        private final DigestAlgorithm defaultPrf;

        public BasePBKDF2(String algName, PasswordConverter passwordConverter)
        {
            this(algName, passwordConverter, FipsSHS.Algorithm.SHA1_HMAC);
        }

        public BasePBKDF2(String algName, PasswordConverter passwordConverter, DigestAlgorithm defaultPrf)
        {
            this.algName = algName;
            this.passwordConverter = passwordConverter;
            this.defaultPrf = defaultPrf;
        }

        public SecretKey engineGenerateSecret(
            KeySpec keySpec)
            throws InvalidKeySpecException
        {
            if (keySpec instanceof PBEKeySpec)
            {
                PBEKeySpec pbeSpec = (PBEKeySpec)keySpec;

                if (pbeSpec.getSalt() == null)
                {
                    throw new InvalidKeySpecException("Missing required salt");
                }

                if (pbeSpec.getKeyLength() <= 0)
                {
                    throw new InvalidKeySpecException("Positive key length required: "
                        + pbeSpec.getKeyLength());
                }

                DigestAlgorithm prfAlg = defaultPrf;
                String keyAlg = algName;

                if (pbeSpec instanceof PBKDF2KeySpec && !((PBKDF2KeySpec)pbeSpec).isDefaultPrf())
                {
                    PBKDF2KeySpec spec = (PBKDF2KeySpec)pbeSpec;
                    prfAlg = getPrfAlgorithm(spec.getPrf().getAlgorithm());
                    if (passwordConverter == PasswordConverter.UTF8)
                    {
                        keyAlg = "PBKDF2withHmac" + convertToJCA(prfAlg) + "andUTF8";
                    }
                    else
                    {
                        keyAlg = "PBKDF2withHmac" + convertToJCA(prfAlg) + "and8BIT";
                    }
                }

                PasswordBasedDeriver deriver;
                if (prfAlg instanceof FipsAlgorithm)
                {
                    deriver = new FipsPBKD.DeriverFactory().createDeriver(
                        FipsPBKD.PBKDF2.using((FipsDigestAlgorithm)prfAlg, passwordConverter, pbeSpec.getPassword())
                            .withSalt(pbeSpec.getSalt()).withIterationCount(pbeSpec.getIterationCount())
                    );
                }
                else
                {
                    deriver = new PBKD.DeriverFactory().createDeriver(
                        PBKD.PBKDF2.using(prfAlg, passwordConverter, pbeSpec.getPassword())
                            .withSalt(pbeSpec.getSalt()).withIterationCount(pbeSpec.getIterationCount())
                    );
                }

                return new PBKDFPBEKey(deriver.deriveKey(PasswordBasedDeriver.KeyType.CIPHER, (pbeSpec.getKeyLength() + 7) / 8), keyAlg, pbeSpec);
            }

            throw new InvalidKeySpecException("Invalid KeySpec: " + keySpec.getClass().getName());
        }
    }

    private static String convertToJCA(Algorithm algorithm)
    {
        String algName = algorithm.getName();
        int slash = algName.indexOf('/');
        int dash = algName.indexOf('-');

        if (dash > 0)
        {
            return algName.substring(0, dash) + algName.substring(dash + 1, slash);
        }
        else
        {
            return algName.substring(0, slash);
        }
    }

    private static DigestAlgorithm getPrfAlgorithm(ASN1ObjectIdentifier algorithm)
        throws InvalidKeySpecException
    {
        if (algorithm.equals(CryptoProObjectIdentifiers.gostR3411Hmac))
        {
            return SecureHash.Algorithm.GOST3411_HMAC;
        }
        else if (algorithm.equals(PKCSObjectIdentifiers.id_hmacWithSHA1))
        {
            return FipsSHS.Algorithm.SHA1_HMAC;
        }
        else if (algorithm.equals(PKCSObjectIdentifiers.id_hmacWithSHA224))
        {
            return FipsSHS.Algorithm.SHA224_HMAC;
        }
        else if (algorithm.equals(PKCSObjectIdentifiers.id_hmacWithSHA256))
        {
            return FipsSHS.Algorithm.SHA256_HMAC;
        }
        else if (algorithm.equals(PKCSObjectIdentifiers.id_hmacWithSHA384))
        {
            return FipsSHS.Algorithm.SHA384_HMAC;
        }
        else if (algorithm.equals(PKCSObjectIdentifiers.id_hmacWithSHA512))
        {
            return FipsSHS.Algorithm.SHA512_HMAC;
        }

        throw new InvalidKeySpecException("Invalid KeySpec: unknown PRF algorithm " + algorithm);
    }

    static byte[] getSecretKey(SecretKey pbeKey, PBEParameterSpec pbeSpec, PasswordBasedDeriver.KeyType keyType, int keySizeInBits)
    {
        PasswordBasedDeriver deriver = new FipsPBKD.DeriverFactory().createDeriver(
            FipsPBKD.PBKDF2.using(FipsSHS.Algorithm.SHA1_HMAC, pbeKey.getEncoded())
                .withIterationCount(pbeSpec.getIterationCount()).withSalt(pbeSpec.getSalt())
        );

        return deriver.deriveKey(keyType, (keySizeInBits + 7) / 8);
    }
}
