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
import org.bouncycastle.asn1.pkcs.PBEParameter;
import org.bouncycastle.crypto.DigestAlgorithm;
import org.bouncycastle.crypto.PasswordBasedDeriver;
import org.bouncycastle.crypto.PasswordConverter;
import org.bouncycastle.crypto.general.PBKD;

class ProvPBEPBKDF1
    extends AlgorithmProvider
{
    private static final String PREFIX = ProvPBEPBKDF1.class.getName();

    public void configure(BouncyCastleFipsProvider provider)
    {
        provider.addAlgorithmImplementation("AlgorithmParameters.PBKDF1", PREFIX + "$AlgParams", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new AlgParams();
            }
        }));
    }

    public static class AlgParams
        extends BaseAlgorithmParameters
    {
        PBEParameter params;

        protected byte[] localGetEncoded()
            throws IOException
        {
            return params.getEncoded(ASN1Encoding.DER);
        }

        protected AlgorithmParameterSpec localEngineGetParameterSpec(
            Class paramSpec)
            throws InvalidParameterSpecException
        {
            if (paramSpec == PBEParameterSpec.class || paramSpec == AlgorithmParameterSpec.class)
            {
                return new PBEParameterSpec(params.getSalt(),
                                params.getIterationCount().intValue());
            }

            throw new InvalidParameterSpecException("AlgorithmParameterSpec not recognized: " + paramSpec.getName());
        }

        protected void engineInit(
            AlgorithmParameterSpec paramSpec)
            throws InvalidParameterSpecException
        {
            if (!(paramSpec instanceof PBEParameterSpec))
            {
                throw new InvalidParameterSpecException("PBEParameterSpec required to initialise a PBKDF1 PBE parameters algorithm parameters object");
            }

            PBEParameterSpec pbeSpec = (PBEParameterSpec)paramSpec;

            try
            {
                this.params = new PBEParameter(pbeSpec.getSalt(), pbeSpec.getIterationCount());
            }
            catch (Exception e)
            {
                throw new InvalidParameterSpecException(e.getMessage());
            }
        }

        protected void localInit(
            byte[] params)
            throws IOException
        {
            this.params = PBEParameter.getInstance(params);
        }

        protected String engineToString()
        {
            return "PBKDF1 Parameters";
        }
    }

    public static class FixedPBKDF1
        extends BaseKDFSecretKeyFactory
    {
        private final String algorithm;
        private final PasswordConverter passwordConverter;
        private final DigestAlgorithm prfAlg;
        private final int keySizeInBits;

        public FixedPBKDF1(String algorithm, PasswordConverter passwordConverter, DigestAlgorithm prfAlg, int keySizeInBits)
        {
            this.algorithm = algorithm;
            this.passwordConverter = passwordConverter;
            this.prfAlg = prfAlg;
            this.keySizeInBits = keySizeInBits;
        }

        protected SecretKey engineGenerateSecret(
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

                PasswordBasedDeriver deriver = new PBKD.DeriverFactory().createDeriver(
                                        PBKD.PBKDF1.using(prfAlg, passwordConverter, pbeSpec.getPassword())
                                            .withSalt(pbeSpec.getSalt()).withIterationCount(pbeSpec.getIterationCount())
                );

                return new PBKDFPBEKey(deriver.deriveKey(PasswordBasedDeriver.KeyType.CIPHER, (keySizeInBits + 7) / 8), algorithm, pbeSpec);
            }

            throw new InvalidKeySpecException("Invalid KeySpec: " + keySpec.getClass().getName());
        }
    }

    static byte[] getSecretKey(SecretKey pbeKey, PBEParameterSpec pbeSpec, DigestAlgorithm prf, PasswordBasedDeriver.KeyType keyType, int keySizeInBits)
    {
        PasswordBasedDeriver deriver = new PBKD.DeriverFactory().createDeriver(
            PBKD.PBKDF1.using(prf, pbeKey.getEncoded())
                .withIterationCount(pbeSpec.getIterationCount()).withSalt(pbeSpec.getSalt())
        );

        return deriver.deriveKey(keyType, (keySizeInBits + 7) / 8);
    }

    static byte[][] getSecretKeyAndIV(SecretKey pbeKey, PBEParameterSpec pbeSpec, DigestAlgorithm prf, PasswordBasedDeriver.KeyType keyType, int keySizeInBits, int ivvSizeInBits)
    {
        PasswordBasedDeriver deriver = new PBKD.DeriverFactory().createDeriver(
            PBKD.PBKDF1.using(prf, pbeKey.getEncoded())
                .withIterationCount(pbeSpec.getIterationCount()).withSalt(pbeSpec.getSalt())
        );

        return deriver.deriveKeyAndIV(keyType, (keySizeInBits + 7) / 8, (ivvSizeInBits + 7) / 8);
    }
}
