package org.bouncycastle.crypto.internal.params;

import java.math.BigInteger;

public class DhPrivateKeyParameters
    extends DhKeyParameters
{
    private BigInteger      x;

    public DhPrivateKeyParameters(
        BigInteger x,
        DhParameters params)
    {
        super(true, params);

        this.x = x;
    }   

    public BigInteger getX()
    {
        return x;
    }
}
