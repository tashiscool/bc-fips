package org.bouncycastle.crypto.internal.params;

import java.math.BigInteger;

public class DhPublicKeyParameters
    extends DhKeyParameters
{
    private BigInteger      y;

    public DhPublicKeyParameters(
        BigInteger y,
        DhParameters params)
    {
        super(false, params);

        this.y = y;
    }   

    public BigInteger getY()
    {
        return y;
    }
}
