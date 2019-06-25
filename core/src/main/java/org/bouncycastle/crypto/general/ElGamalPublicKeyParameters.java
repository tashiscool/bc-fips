package org.bouncycastle.crypto.general;

import java.math.BigInteger;

class ElGamalPublicKeyParameters
    extends ElGamalKeyParameters
{
    private final BigInteger      y;

    public ElGamalPublicKeyParameters(
        BigInteger      y,
        ElGamalParameters    params)
    {
        super(false, params);

        this.y = y;
    }   

    public BigInteger getY()
    {
        return y;
    }
}
