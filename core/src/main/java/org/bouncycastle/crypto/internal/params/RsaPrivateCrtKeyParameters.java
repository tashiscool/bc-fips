/***************************************************************/
/******    DO NOT EDIT THIS CLASS bc-java SOURCE FILE     ******/
/***************************************************************/
package org.bouncycastle.crypto.internal.params;

import java.math.BigInteger;

public class RsaPrivateCrtKeyParameters
    extends RsaKeyParameters
{
    private BigInteger  e;
    private BigInteger  p;
    private BigInteger  q;
    private BigInteger  dP;
    private BigInteger  dQ;
    private BigInteger  qInv;

    /**
     * 
     */
    public RsaPrivateCrtKeyParameters(
        BigInteger  modulus,
        BigInteger  publicExponent,
        BigInteger  privateExponent,
        BigInteger  p,
        BigInteger  q,
        BigInteger  dP,
        BigInteger  dQ,
        BigInteger  qInv)
    {
        super(true, modulus, privateExponent);

        this.e = publicExponent;
        this.p = p;
        this.q = q;
        this.dP = dP;
        this.dQ = dQ;
        this.qInv = qInv;
    }

    public BigInteger getPublicExponent()
    {
        return e;
    }

    public BigInteger getP()
    {
        return p;
    }

    public BigInteger getQ()
    {
        return q;
    }

    public BigInteger getDP()
    {
        return dP;
    }

    public BigInteger getDQ()
    {
        return dQ;
    }

    public BigInteger getQInv()
    {
        return qInv;
    }
}
