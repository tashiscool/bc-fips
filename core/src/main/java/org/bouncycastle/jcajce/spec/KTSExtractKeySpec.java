package org.bouncycastle.jcajce.spec;

import java.security.PrivateKey;
import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.fips.FipsKDF;
import org.bouncycastle.util.Arrays;

/**
 * KeySpec for use with secret key extraction with a SecretKeyFactory supporting KTS.
 */
public class KTSExtractKeySpec
    extends KTSKeySpec
{
    /**
     * Builder class for creating a KTSExtractKeySpec.
     */
    public static final class Builder
    {
        private final PrivateKey privateKey;
        private final String algorithmName;
        private final int keySizeInBits;
        private final byte[] encapsulation;
        private final byte[] otherInfo;

        private String macAlgorithm;
        private int macKeySizeInBits;
        private AlgorithmParameterSpec parameterSpec;
        private AlgorithmIdentifier kdfAlgorithm;

        /**
         * Basic builder.
         *
         * @param privateKey the private key to use to extract the secret from the encapsulation.
         * @param encapsulation the encapsulated secret.
         * @param algorithmName the algorithm name for the secret key we wish to calculate.
         * @param keySizeInBits the size of the key we want to produce in bits.
         */
        public Builder(PrivateKey privateKey, byte[] encapsulation, String algorithmName, int keySizeInBits)
        {
            this(privateKey, encapsulation, algorithmName, keySizeInBits, null);
        }

        /**
         * Basic builder.
         *
         * @param privateKey the private key to use to extract the secret from the encapsulation.
         * @param encapsulation the encapsulated secret.
         * @param algorithmName the algorithm name for the secret key we wish to calculate.
         * @param keySizeInBits the size of the key we want to produce in bits.
         */
        public Builder(PrivateKey privateKey, byte[] encapsulation, String algorithmName, int keySizeInBits, byte[] otherInfo)
        {
            this.privateKey = privateKey;
            this.algorithmName = algorithmName;
            this.keySizeInBits = keySizeInBits;
            this.encapsulation = Arrays.clone(encapsulation);
            this.kdfAlgorithm = createAlgId(KDF3.withPRF(FipsKDF.AgreementKDFPRF.SHA256));
            this.otherInfo = copyOtherInfo(otherInfo);
        }

        /**
         * Set the KDF algorithm and digest algorithm for key generation (ignored for OAEP).
         *
         * @param kdfAlgorithm the KDF algorithm to apply.
         * @return the current Builder instance.
         */
        public Builder withKdfAlgorithm(FipsKDF.AgreementKDFParametersBuilder kdfAlgorithm)
        {
            this.kdfAlgorithm = createAlgId(kdfAlgorithm);

            return this;
        }

        /**
         * Set the KDF algorithm and digest algorithm for key generation (ignored for OAEP).
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
         * Set the MAC algorithm name and its associated key size for the MAC key in the encapsulation.
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
         * Set the algorithm parameter spec to be used with the private key.
         *
         * @param parameterSpec the algorithm parameter spec to be used in decryption.
         * @return the current Builder instance.
         */
        public Builder withParameterSpec(AlgorithmParameterSpec parameterSpec)
        {
            this.parameterSpec = parameterSpec;

            return this;
        }

        /**
         * Build the new key spec.
         *
         * @return a new key spec configured according to the builder state.
         */
        public KTSExtractKeySpec build()
        {
            return new KTSExtractKeySpec(privateKey, encapsulation, algorithmName, keySizeInBits, macAlgorithm,
                macKeySizeInBits, parameterSpec, kdfAlgorithm, otherInfo);
        }
    }

    private final PrivateKey privateKey;
    private final byte[] encapsulation;

    private KTSExtractKeySpec(PrivateKey privateKey, byte[] encapsulation, String algorithmName, int keySize, String macAlgorithm, int macKeySizeInBits,
                              AlgorithmParameterSpec parameterSpec, AlgorithmIdentifier kdfAlgorithm, byte[] otherInfo)
    {
        super(algorithmName, keySize, macAlgorithm, macKeySizeInBits, parameterSpec, kdfAlgorithm, otherInfo);
        this.privateKey = privateKey;
        this.encapsulation = encapsulation;
    }

    /**
     * Return the encapsulation of the secret associated with this key spec.
     *
     * @return the secret encapsulation.
     */
    public byte[] getEncapsulation()
    {
        return Arrays.clone(encapsulation);
    }

    /**
     * Return the decryption private key to be used by the SecretKeyFactory used with this key spec.
     *
     * @return the private key to be used to decrypt the encapsulation.
     */
    public PrivateKey getPrivateKey()
    {
        return privateKey;
    }
}
