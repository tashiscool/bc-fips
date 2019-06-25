/***************************************************************/
/******    DO NOT EDIT THIS CLASS bc-java SOURCE FILE     ******/
/***************************************************************/
package org.bouncycastle.crypto.general;

import java.math.BigInteger;

import org.bouncycastle.crypto.internal.CipherParameters;

class Gost3410Parameters
   implements CipherParameters
{
    private BigInteger              p;
    private BigInteger              q;
    private BigInteger              a;

    public Gost3410Parameters(
        BigInteger  p,
        BigInteger  q,
        BigInteger  a)
    {
        this.p = p;
        this.q = q;
        this.a = a;
    }

    public BigInteger getP()
    {
        return p;
    }

    public BigInteger getQ()
    {
        return q;
    }

    public BigInteger getA()
    {
        return a;
    }

    public int hashCode()
    {
        return p.hashCode() ^ q.hashCode() ^ a.hashCode();
    }

    public boolean equals(
        Object  obj)
    {
        if (!(obj instanceof Gost3410Parameters))
        {
            return false;
        }

        Gost3410Parameters    pm = (Gost3410Parameters)obj;

        return (pm.getP().equals(p) && pm.getQ().equals(q) && pm.getA().equals(a));
    }
}
