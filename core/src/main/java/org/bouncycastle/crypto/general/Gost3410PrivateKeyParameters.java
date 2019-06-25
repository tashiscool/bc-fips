/***************************************************************/
/******    DO NOT EDIT THIS CLASS bc-java SOURCE FILE     ******/
/***************************************************************/
package org.bouncycastle.crypto.general;

import java.math.BigInteger;

class Gost3410PrivateKeyParameters
        extends Gost3410KeyParameters
{
    private BigInteger      x;

    public Gost3410PrivateKeyParameters(
        BigInteger      x,
        Gost3410Parameters   params)
    {
        super(true, params);

        this.x = x;
    }

    public BigInteger getX()
    {
        return x;
    }
}
