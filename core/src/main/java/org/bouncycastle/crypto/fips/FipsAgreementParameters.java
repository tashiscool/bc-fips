package org.bouncycastle.crypto.fips;

import org.bouncycastle.util.Arrays;

/**
 * Base parameters class for Diffie-Hellman and MQV based key agreement algorithms.
 */
public class FipsAgreementParameters
    extends FipsParameters
{
    final FipsAlgorithm digestAlgorithm;
    final FipsKDF.PRF prfAlgorithm;
    final byte[] salt;
    final FipsKDF.AgreementKDFParametersBuilder kdfType;
    final int outputSize;

    /**
     * Constructor which specifies returning a digest of the raw secret on agreement calculation.
     *
     * @param agreementAlgorithm the agreement algorithm these parameters are for.
     * @param digestAlgorithm the digest algorithm to use.
     */
    FipsAgreementParameters(FipsAlgorithm agreementAlgorithm, FipsAlgorithm digestAlgorithm)
    {
        super(agreementAlgorithm);

        this.digestAlgorithm = digestAlgorithm;
        this.prfAlgorithm = null;
        this.salt = null;
        this.kdfType = null;
        this.outputSize = 0;
    }

    /**
     * Constructor which specifies returning a MAC/HMAC of the raw secret on agreement calculation using one of the
     * standard PRFs as described in SP800-56C.
     *
     * @param agreementAlgorithm the agreement algorithm these parameters are for.
     * @param prfAlgorithm the MAC/HMAC algorithm to use.
     * @param salt the byte string to key the MAC/HMAC with.
     */
    FipsAgreementParameters(FipsAlgorithm agreementAlgorithm, FipsKDF.PRF prfAlgorithm, byte[] salt)
    {
        super(agreementAlgorithm);

        if (prfAlgorithm == null)
        {
            throw new NullPointerException("prfAlgorithm cannot be null");
        }
        if (salt == null)
        {
            throw new NullPointerException("salt cannot be null");
        }

        this.digestAlgorithm = null;
        this.prfAlgorithm = prfAlgorithm;
        this.salt = Arrays.clone(salt);
        this.kdfType = null;
        this.outputSize = 0;
    }

    /**
     * Constructor with a KDF to process the Z value with. The outputSize parameter determines how many bytes
     * will be generated.
     *
     * @param kdfType KDF algorithm type to use for parameter creation.
     * @param iv the iv parameter for KDF initialization.
     * @param outputSize the size of the output to be generated from the KDF.
     */
    FipsAgreementParameters(FipsAlgorithm agreementAlgorithm, FipsKDF.AgreementKDFParametersBuilder kdfType, byte[] iv, int outputSize)
    {
        super(agreementAlgorithm);

        if (kdfType == null)
        {
            throw new NullPointerException("kdfType cannot be null");
        }
        if (outputSize <= 0)
        {
            throw new IllegalArgumentException("outputSize must be greater than zero");
        }

        this.digestAlgorithm = null;
        this.prfAlgorithm = null;
        this.salt = Arrays.clone(iv);
        this.kdfType = kdfType;
        this.outputSize = outputSize;
    }

    /**
     * Return the digest algorithm ID associated with these parameters.
     *
     * @return the digest algorithm ID, null if not present.
     */
    public FipsAlgorithm getDigestAlgorithm()
    {
        return digestAlgorithm;
    }

    /**
     * Return the PRF associated with these parameters.
     *
     * @return the PRF ID, null if not present.
     */
    public FipsKDF.PRF getPrfAlgorithm()
    {
        return prfAlgorithm;
    }

    /**
     * Return the salt/iv associated with these parameters.
     *
     * @return the salt, null if not present.
     */
    public byte[] getSalt()
    {
        return Arrays.clone(salt);
    }
}
