package org.bouncycastle.jcajce.spec;

import javax.crypto.spec.PBEKeySpec;

import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.DigestAlgorithm;

/**
 * PBEKeySpec allowing for the use of alternate PRFs with PBKDF2.
 */
public class PBKDF2KeySpec
    extends PBEKeySpec
{
    private static final AlgorithmIdentifier defaultPRF = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_hmacWithSHA1, DERNull.INSTANCE);

    private AlgorithmIdentifier prf;

    /**
     * Base constructor with the default PRF.
     *
     * @param password password.
     * @param salt salt to use.
     * @param iterationCount iteration count for PBE algorithm.
     * @param keySize keySize in bits.
     */
    public PBKDF2KeySpec(char[] password, byte[] salt, int iterationCount, int keySize)
    {
        this(password, salt, iterationCount, keySize, defaultPRF);
    }

    /**
     * Constructor that allows specifying a PRF using an Algorithm.
     *
     * @param password password.
     * @param salt salt to use.
     * @param iterationCount iteration count for PBE algorithm.
     * @param keySize keySize in bits.
     * @param prfAlgorithm Algorithm identifying the PRF to use.
     */
    public PBKDF2KeySpec(char[] password, byte[] salt, int iterationCount, int keySize, DigestAlgorithm prfAlgorithm)
    {
        this(password, salt, iterationCount, keySize, PrfUtils.getAlgorithmIdentifier(prfAlgorithm));
    }

    /**
     * Constructor that allows specifying a PRF.
     *
     * @param password password.
     * @param salt salt to use.
     * @param iterationCount iteration count for PBE algorithm.
     * @param keySize keySize in bits.
     * @param prf AlgorithmIdentifier for the PRF to use.
     */
    public PBKDF2KeySpec(char[] password, byte[] salt, int iterationCount, int keySize, AlgorithmIdentifier prf)
    {
        super(password, salt, iterationCount, keySize);

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
     * Return an AlgorithmIdentifier representing the PRF.
     *
     * @return the PRF's AlgorithmIdentifier.
     */
    public AlgorithmIdentifier getPrf()
    {
        return prf;
    }
}
