/***************************************************************/
/******    DO NOT EDIT THIS CLASS bc-java SOURCE FILE     ******/
/***************************************************************/
package org.bouncycastle.jcajce.spec;

import java.math.BigInteger;
import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.crypto.DigestAlgorithm;
import org.bouncycastle.crypto.fips.FipsSHS;
import org.bouncycastle.util.Arrays;

/**
 * Parameter spec for guiding the generation of DSA Domain Parameters.
 */
public class DSADomainParametersGenerationParameterSpec
    implements AlgorithmParameterSpec
{
    public static final int DIGITAL_SIGNATURE_USAGE = 1;
    public static final int KEY_ESTABLISHMENT_USAGE = 2;

    private final int l;
    private final int n;
    private final int certainty;
    private final BigInteger p;
    private final BigInteger q;
    private final byte[] seed;
    private final int usageIndex;
    private final DigestAlgorithm digestAlgorithm;

    /**
     * Construct without a usage index, this will do a random construction of G.
     *
     * @param L desired length of prime P in bits (the effective key size).
     * @param N desired length of prime Q in bits.
     * @param certainty certainty level for prime number generation.
     */
    public DSADomainParametersGenerationParameterSpec(
        int L,
        int N,
        int certainty)
    {
        this(L, N, certainty, -1);
    }

    /**
     * Construct for a specific usage index - this has the effect of using verifiable canonical generation of G.
     *
     * @param L desired length of prime P in bits (the effective key size).
     * @param N desired length of prime Q in bits.
     * @param certainty certainty level for prime number generation.
     * @param usageIndex a valid usage index.
     */
    public DSADomainParametersGenerationParameterSpec(
        int L,
        int N,
        int certainty,
        int usageIndex)
    {
        this(FipsSHS.Algorithm.SHA256, L, N, certainty, null, null, null, usageIndex);
    }

    /**
     * Construct using a specific value of p and q - this will do a random construction of g.
     *
     * @param p the prime p.
     * @param q the sub-prime q.
     */
    public DSADomainParametersGenerationParameterSpec(BigInteger p, BigInteger q)
    {
        this(FipsSHS.Algorithm.SHA256, p.bitLength(), q.bitLength(), 0, p, q, null, -1);
    }

    /**
     * Construct using a specific value of p and q, but with a seed and usageIndex as well - this has the
     * effect of using verifiable canonical generation of G.
     *
     * @param p the prime p.
     * @param q the sub-prime q.
     * @param seed the seed used to generate p and q.
     * @param usageIndex a valid usage index.
     */
    public DSADomainParametersGenerationParameterSpec(BigInteger p, BigInteger q, byte[] seed, int usageIndex)
    {
        this(FipsSHS.Algorithm.SHA256, p.bitLength(), q.bitLength(), 0, p, q, Arrays.clone(seed), usageIndex);
    }

    private DSADomainParametersGenerationParameterSpec(DigestAlgorithm digestAlgorithm, int L, int N, int certainty, BigInteger p, BigInteger q, byte[] seed, int usageIndex)
    {
        this.digestAlgorithm = digestAlgorithm;
        this.l = L;
        this.n = N;
        this.certainty = certainty;
        this.p = p;
        this.q = q;
        this.seed = seed;
        this.usageIndex = usageIndex;
    }

    /**
     * Create a spec which also specifies a specific digest algorithm to use for parameters generation.
     *
     * @param digestAlgorithm the specific digest algorithm to use.
     * @return a new parameters generator spec.
     */
    public DSADomainParametersGenerationParameterSpec withDigestAlgorithm(DigestAlgorithm digestAlgorithm)
    {
        return new DSADomainParametersGenerationParameterSpec(digestAlgorithm, l, n, certainty, p, q, seed, usageIndex);
    }

    public int getL()
    {
        return l;
    }

    public int getN()
    {
        return n;
    }

    public int getCertainty()
    {
        return certainty;
    }

    public int getUsageIndex()
    {
        return usageIndex;
    }

    public BigInteger getP()
    {
        return p;
    }

    public BigInteger getQ()
    {
        return q;
    }

    public byte[] getSeed()
    {
        return Arrays.clone(seed);
    }

    public DigestAlgorithm getDigestAlgorithm()
    {
        return digestAlgorithm;
    }
}
