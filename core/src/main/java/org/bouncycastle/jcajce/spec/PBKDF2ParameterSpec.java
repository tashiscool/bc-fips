package org.bouncycastle.jcajce.spec;

import javax.crypto.spec.PBEParameterSpec;

import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.DigestAlgorithm;

/**
 * PBEParameterSpec allowing for the use of alternate PRFs with PBKDF2.
 */
public class PBKDF2ParameterSpec
    extends PBEParameterSpec
{
    private static final AlgorithmIdentifier defaultPRF = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_hmacWithSHA1, DERNull.INSTANCE);

    private final int keySize;
    private final AlgorithmIdentifier prf;

    /**
     * Base constructor with the default PRF.
     *
     * @param salt salt to use.
     * @param iterationCount iteration count for PBE algorithm.
     * @param keySize keySize in bits.
     */
    public PBKDF2ParameterSpec(byte[] salt, int iterationCount, int keySize)
    {
        this(salt, iterationCount, keySize, defaultPRF);
    }

    /**
     * Constructor that allows specifying a PRF using an Algorithm.
     *
     * @param salt salt to use.
     * @param iterationCount iteration count for PBE algorithm.
     * @param keySize keySize in bits.
     * @param prfAlgorithm Algorithm identifying the PRF to use.
     */
    public PBKDF2ParameterSpec(byte[] salt, int iterationCount, int keySize, DigestAlgorithm prfAlgorithm)
    {
        this(salt, iterationCount, keySize, PrfUtils.getAlgorithmIdentifier(prfAlgorithm));
    }

    /**
     * Constructor that allows specifying a PRF.
     *
     * @param salt salt to use.
     * @param iterationCount iteration count for PBE algorithm.
     * @param keySize keySize in bits.
     * @param prf AlgorithmIdentifier for the PRF to use.
     */
    public PBKDF2ParameterSpec(byte[] salt, int iterationCount, int keySize, AlgorithmIdentifier prf)
    {
        super(salt, iterationCount);

        if (keySize % 8 != 0)
        {
            throw new IllegalArgumentException("keySize must be a multiple of 8");
        }

        this.keySize = keySize;
        this.prf = prf;
    }

    /**
     * Return true if this spec is for the default PRF (HmacSHA1), false otherwise.
     *
     * @return true if this spec uses the default PRF, false otherwise.
     */
    public boolean isDefaultPrf()
    {
        return defaultPRF.equals(prf);
    }

    /**
     * Return the key size (in bits) for the key to be derived.
     *
     * @return the size of the generated key required.
     */
    public int getKeySize()
    {
        return keySize;
    }

    /**
     * Return an AlgorithmIdentifier representing the PRF.
     *
     * @return the PRF's AlgorithmIdentifier.
     */
    public AlgorithmIdentifier getPrf()
    {
        return prf;
    }
}
