package org.bouncycastle.crypto.internal.params;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;

public class EcDomainParameters
    implements ECConstants
{
    private ECCurve     curve;
    private byte[]      seed;
    private ECPoint     G;
    private BigInteger  n;
    private BigInteger  h;

    public EcDomainParameters(
        ECCurve curve,
        ECPoint G,
        BigInteger n,
        BigInteger h)
    {
        this(curve, G, n, h, null);
    }

    public EcDomainParameters(
        ECCurve curve,
        ECPoint G,
        BigInteger n,
        BigInteger h,
        byte[] seed)
    {
        this.curve = curve;
        this.G = G.normalize();
        this.n = n;
        this.h = h;
        this.seed = seed;
    }

    public ECCurve getCurve()
    {
        return curve;
    }

    public ECPoint getG()
    {
        return G;
    }

    public BigInteger getN()
    {
        return n;
    }

    public BigInteger getH()
    {
        return h;
    }

    public byte[] getSeed()
    {
        return Arrays.clone(seed);
    }

    public boolean equals(
        Object  obj)
    {
        if (this == obj)
        {
            return true;
        }

        if ((obj instanceof EcDomainParameters))
        {
            EcDomainParameters pm = (EcDomainParameters)obj;

            return this.curve.equals(pm.curve) && this.G.equals(pm.G) && this.n.equals(pm.n) && this.h.equals(pm.h);
        }

        return false;
    }

    public int hashCode()
    {
        int hc = curve.hashCode();

        hc += 37 * G.hashCode();
        hc += 37 * n.hashCode();
        hc += 37 * h.hashCode();

        return hc;
    }

}
