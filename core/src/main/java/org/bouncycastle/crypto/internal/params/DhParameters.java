package org.bouncycastle.crypto.internal.params;

import java.math.BigInteger;

import org.bouncycastle.crypto.internal.CipherParameters;

public class DhParameters
    implements CipherParameters
{
    private static final int DEFAULT_MINIMUM_LENGTH = 160;

    private final BigInteger              g;
    private final BigInteger              p;
    private final BigInteger              q;
    private final BigInteger              j;
    private final int                     m;
    private final int                     l;

    private static int getDefaultMParam(
        int lParam)
    {
        if (lParam == 0)
        {
            return DEFAULT_MINIMUM_LENGTH;
        }

        return lParam < DEFAULT_MINIMUM_LENGTH ? lParam : DEFAULT_MINIMUM_LENGTH;
    }

    public DhParameters(
        BigInteger p,
        BigInteger g,
        BigInteger q)
    {
        this(p, g, q, getDefaultMParam(0), 0, null);
    }

    public DhParameters(
        BigInteger p,
        BigInteger g,
        BigInteger q,
        BigInteger j)
    {
        this(p, g, q, DEFAULT_MINIMUM_LENGTH, 0, j);
    }

    public DhParameters(
        BigInteger p,
        BigInteger g,
        BigInteger q,
        int m,
        int l,
        BigInteger j)
    {
        if (l != 0)
        {
            if (l > p.bitLength())
            {
                throw new IllegalArgumentException("when l value specified, it must satisfy 2^(l-1) <= p");
            }
            if (l < m)
            {
                throw new IllegalArgumentException("when l value specified, it may not be less than m value");
            }
        }

        this.g = g;
        this.p = p;
        this.q = q;
        this.m = m;
        this.l = l;
        this.j = j;
    }

    public BigInteger getP()
    {
        return p;
    }

    public BigInteger getG()
    {
        return g;
    }

    public BigInteger getQ()
    {
        return q;
    }

    /**
     * Return the subgroup factor J.
     *
     * @return subgroup factor
     */
    public BigInteger getJ()
    {
        return j;
    }

    /**
     * Return the minimum length of the private value.
     *
     * @return the minimum length of the private value in bits.
     */
    public int getM()
    {
        return m;
    }

    /**
     * Return the private value length in bits - if set, zero otherwise
     *
     * @return the private value length in bits, zero otherwise.
     */
    public int getL()
    {
        return l;
    }

    public boolean equals(
        Object  obj)
    {
        if (obj == this)
        {
            return true;
        }

        if (obj instanceof DhParameters)
        {
            DhParameters pm = (DhParameters)obj;

            if (this.getQ() != null)
            {
                if (!this.getQ().equals(pm.getQ()))
                {
                    return false;
                }
            }
            else
            {
                if (pm.getQ() != null)
                {
                    return false;
                }
            }

            return pm.getP().equals(p) && pm.getG().equals(g);
        }

        return false;
    }
    
    public int hashCode()
    {
        int hc = getP().hashCode();

        hc += 37 * getG().hashCode();
        hc += 37 * (getQ() != null ? getQ().hashCode() : 0);

        return hc;
    }
}
