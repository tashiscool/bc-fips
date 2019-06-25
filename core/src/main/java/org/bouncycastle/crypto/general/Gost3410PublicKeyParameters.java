/***************************************************************/
/******    DO NOT EDIT THIS CLASS bc-java SOURCE FILE     ******/
/***************************************************************/
package org.bouncycastle.crypto.general;

import java.math.BigInteger;

class Gost3410PublicKeyParameters
        extends Gost3410KeyParameters
{
    private BigInteger      y;

    public Gost3410PublicKeyParameters(
        BigInteger      y,
        Gost3410Parameters   params)
    {
        super(false, params);

        this.y = y;
    }

    public BigInteger getY()
    {
        return y;
    }
}
