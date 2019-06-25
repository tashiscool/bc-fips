package org.bouncycastle.jcajce.spec;

import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.fips.FipsKDF;

/**
 * KeySpec for use with secret key generation with a SecretKeyFactory supporting KTS.
 */
public class KTSGenerateKeySpec
    extends KTSKeySpec
{
    /**
     * Builder class for creating a KTSGenerateKeySpec.
     */
    public static final class Builder
    {
        private final PublicKey publicKey;
        private final String algorithmName;
        private final int keySizeInBits;

        private String macAlgorithm;
        private int macKeySizeInBits;

        private SecureRandom random;
        private AlgorithmParameterSpec parameterSpec;
        private AlgorithmIdentifier kdfAlgorithm;
        private byte[] otherInfo;

        /**
         * Basic builder.
         *
         * @param publicKey     the public key to be used for encryption/encapsulation generation.
         * @param algorithmName the algorithm name for the secret key we wish to calculate.
         * @param keySizeInBits the size of the key we want to produce in bits.
         */
        public Builder(PublicKey publicKey, String algorithmName, int keySizeInBits)
        {
            this(publicKey, algorithmName, keySizeInBits, null);
        }

        /**
         * Basic builder.
         *
         * @param publicKey     the public key to be used for encryption/encapsulation generation.
         * @param algorithmName the algorithm name for the secret key we wish to calculate.
         * @param keySizeInBits the size of the key we want to produce in bits.
         * @param otherInfo     the otherInfo/IV encoding to be applied to the KDF.
         */
        public Builder(PublicKey publicKey, String algorithmName, int keySizeInBits, byte[] otherInfo)
        {
            this.publicKey = publicKey;
            this.algorithmName = algorithmName;
            this.keySizeInBits = keySizeInBits;
            this.kdfAlgorithm = createAlgId(KDF3.withPRF(FipsKDF.AgreementKDFPRF.SHA256));
            this.otherInfo = copyOtherInfo(otherInfo);
        }

        /**
         * Set the SecureRandom which will be used to generate the secret.
         *
         * @param random the source of randomness for the secret.
         * @return the current Builder instance.
         */
        public Builder withSecureRandom(SecureRandom random)
        {
            this.random = random;

            return this;
        }

        /**
         * Set the MAC algorithm name and its associated key size for the MAC key section of the secret.
         *
         * @param macAlgorithmName name of the MAC algorithm we will use.
         * @param macKeySizeInBits size of the MAC key (in bits)
         * @return the current Builder instance.
         */
        public Builder withMac(String macAlgorithmName, int macKeySizeInBits)
        {
            this.macAlgorithm = macAlgorithmName;
            this.macKeySizeInBits = macKeySizeInBits;

            if (macAlgorithmName != null && macKeySizeInBits <= 0)
            {
                throw new IllegalArgumentException("macKeySizeInBits must be greater than zero");
            }

            return this;
        }

        /**
         * Set the algorithm parameter spec to be used with the public key.
         *
         * @param parameterSpec the algorithm parameter spec to be used in encryption.
         * @return the current Builder instance.
         */
        public Builder withParameterSpec(AlgorithmParameterSpec parameterSpec)
        {
            this.parameterSpec = parameterSpec;

            return this;
        }

        /**
         * Set the KDF algorithm and digest algorithm for key generation.
         *
         * @param kdfBuilder    the KDF algorithm to apply.
         * @return the current Builder instance.
         */
        public Builder withKdfAlgorithm(FipsKDF.AgreementKDFParametersBuilder kdfBuilder)
        {
            this.kdfAlgorithm = createAlgId(kdfBuilder);

            return this;
        }

        /**
         * Set the KDF algorithm and digest algorithm for key generation.
         *
         * @param kdfAlgorithm    the KDF algorithm to apply.
         * @return the current Builder instance.
         */
        public Builder withKdfAlgorithm(AlgorithmIdentifier kdfAlgorithm)
        {
            this.kdfAlgorithm = kdfAlgorithm;

            return this;
        }

        /**
         * Build the new key spec.
         *
         * @return a new key spec configured according to the builder state.
         */
        public KTSGenerateKeySpec build()
        {
            return new KTSGenerateKeySpec(publicKey, algorithmName, keySizeInBits, random, macAlgorithm, macKeySizeInBits, parameterSpec, kdfAlgorithm, otherInfo);
        }
    }

    private final PublicKey publicKey;
    private final SecureRandom random;

    private KTSGenerateKeySpec(PublicKey publicKey, String algorithmName, int keySize, SecureRandom random,
                               String macAlgorithm, int macKeySizeInBits, AlgorithmParameterSpec parameterSpec,
                               AlgorithmIdentifier kdfAlgorithm, byte[] otherInfo)
    {
        super(algorithmName, keySize, macAlgorithm, macKeySizeInBits, parameterSpec, kdfAlgorithm, otherInfo);
        this.publicKey = publicKey;
        this.random = random;
    }

    /**
     * Return the public key to be used to encrypt the secret and make the encapsulation.
     *
     * @return the public key to be used for secret encryption.
     */
    public PublicKey getPublicKey()
    {
        return publicKey;
    }

    /**
     * Return the SecureRandom which will be used to generate the secret.
     *
     * @return the source of randomness for the secret.
     */
    public SecureRandom getSecureRandom()
    {
        return random;
    }
}
