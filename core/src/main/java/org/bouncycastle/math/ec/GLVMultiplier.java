/***************************************************************/
/******    DO NOT EDIT THIS CLASS bc-java SOURCE FILE     ******/
/***************************************************************/
package org.bouncycastle.math.ec;

import java.math.BigInteger;

import org.bouncycastle.math.ec.endo.GLVEndomorphism;

public class GLVMultiplier extends AbstractECMultiplier
{
    protected final ECCurve curve;
    protected final GLVEndomorphism glvEndomorphism;

    public GLVMultiplier(ECCurve curve, GLVEndomorphism glvEndomorphism)
    {
        if (curve == null || curve.getOrder() == null)
        {
            throw new IllegalArgumentException("Need curve with known group order");
        }

        this.curve = curve;
        this.glvEndomorphism = glvEndomorphism;
    }

    protected ECPoint multiplyPositive(ECPoint p, BigInteger k)
    {
        ECCurve c = p.getCurve();
        if (!curve.equals(c))
        {
            throw new IllegalStateException();
        }

        BigInteger order = c.getOrder();
        if (k.compareTo(order) >= 0)
        {
            k = k.mod(order.multiply(c.getCofactor()));
        }

        BigInteger[] ab = glvEndomorphism.decomposeScalar(k);
        BigInteger a = ab[0], b = ab[1];

        ECPointMap pointMap = glvEndomorphism.getPointMap();
        if (glvEndomorphism.hasEfficientPointMap())
        {
            return ECAlgorithms.implShamirsTrickWNaf(p, a, pointMap, b);
        }

        return ECAlgorithms.implShamirsTrickWNaf(p, a, pointMap.map(p), b);
    }
}
