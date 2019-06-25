package org.bouncycastle.crypto.asymmetric;

import java.math.BigInteger;

/**
 * Container class for DSA domain parameters.
 */
public class DSADomainParameters
{
    private BigInteger g;
    private BigInteger q;
    private BigInteger p;
    private DSAValidationParameters validation;

    public DSADomainParameters(
        BigInteger p,
        BigInteger q,
        BigInteger g)
    {
        this.g = g;
        this.p = p;
        this.q = q;
    }

    public DSADomainParameters(
        BigInteger p,
        BigInteger q,
        BigInteger g,
        DSAValidationParameters params)
    {
        this.g = g;
        this.p = p;
        this.q = q;
        this.validation = params;
    }

    public BigInteger getP()
    {
        return p;
    }

    public BigInteger getQ()
    {
        return q;
    }

    public BigInteger getG()
    {
        return g;
    }

    public DSAValidationParameters getValidationParameters()
    {
        return validation;
    }

    public boolean equals(
        Object obj)
    {
        if (!(obj instanceof DSADomainParameters))
        {
            return false;
        }

        DSADomainParameters pm = (DSADomainParameters)obj;

        return (pm.getP().equals(p) && pm.getQ().equals(q) && pm.getG().equals(g));
    }

    public int hashCode()
    {
        int result = g.hashCode();
        result = 31 * result + p.hashCode();
        result = 31 * result + q.hashCode();
        return result;
    }
}
