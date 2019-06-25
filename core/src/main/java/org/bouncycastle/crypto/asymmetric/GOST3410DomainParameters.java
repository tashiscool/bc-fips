package org.bouncycastle.crypto.asymmetric;

import java.math.BigInteger;

/**
 * Domain parameters for GOST R 34.10-1994.
 */
public class GOST3410DomainParameters
{
    private final int keySize;
    private final BigInteger a;
    private final BigInteger q;
    private final BigInteger p;

    /**
     * Base constructor.
     *
     * @param keySize size of the p value (in bits).
     * @param p p value.
     * @param q q value.
     * @param a a value.
     */
    public GOST3410DomainParameters(
        int        keySize,
        BigInteger p,
        BigInteger q,
        BigInteger a)
    {
        this.keySize = keySize;
        this.a = a;
        this.p = p;
        this.q = q;
    }

    /**
     * Return the keySize associated with these parameters.
     *
     * @return the size of the p value in bits.
     */
    public int getKeySize()
    {
        return keySize;
    }

    /**
     * The p value.
     *
     * @return p.
     */
    public BigInteger getP()
    {
        return p;
    }

    /**
     * The q value.
     *
     * @return q.
     */
    public BigInteger getQ()
    {
        return q;
    }

    /**
     * The a value.
     *
     * @return a.
     */
    public BigInteger getA()
    {
        return a;
    }

    public boolean equals(
        Object obj)
    {
        if (!(obj instanceof GOST3410DomainParameters))
        {
            return false;
        }

        GOST3410DomainParameters pm = (GOST3410DomainParameters)obj;

        return keySize == pm.keySize && (pm.getP().equals(p) && pm.getQ().equals(q) && pm.getA().equals(a));
    }

    public int hashCode()
    {
        int result = keySize;
        result = 31 * result + a.hashCode();
        result = 31 * result + p.hashCode();
        result = 31 * result + q.hashCode();
        return result;
    }
}
