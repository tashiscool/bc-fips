/***************************************************************/
/******    DO NOT EDIT THIS CLASS bc-java SOURCE FILE     ******/
/***************************************************************/
package org.bouncycastle.crypto.internal.params;

import java.math.BigInteger;

import org.bouncycastle.crypto.internal.CipherParameters;

public class DsaParameters
    implements CipherParameters
{
    private BigInteger              g;
    private BigInteger              q;
    private BigInteger              p;
    private DsaValidationParameters validation;

    public DsaParameters(
        BigInteger  p,
        BigInteger  q,
        BigInteger  g)
    {
        this.g = g;
        this.p = p;
        this.q = q;
    }   

    public DsaParameters(
        BigInteger              p,
        BigInteger              q,
        BigInteger              g,
        DsaValidationParameters params)
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

    public DsaValidationParameters getValidationParameters()
    {
        return validation;
    }

    public boolean equals(
        Object  obj)
    {
        if (!(obj instanceof DsaParameters))
        {
            return false;
        }

        DsaParameters    pm = (DsaParameters)obj;

        return (pm.getP().equals(p) && pm.getQ().equals(q) && pm.getG().equals(g));
    }
    
    public int hashCode()
    {
        return getP().hashCode() ^ getQ().hashCode() ^ getG().hashCode();
    }
}
