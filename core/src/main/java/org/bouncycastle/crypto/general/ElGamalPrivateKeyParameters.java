/***************************************************************/
/******    DO NOT EDIT THIS CLASS bc-java SOURCE FILE     ******/
/***************************************************************/
package org.bouncycastle.crypto.general;

import java.math.BigInteger;

class ElGamalPrivateKeyParameters
    extends ElGamalKeyParameters
{
    private BigInteger      x;

    public ElGamalPrivateKeyParameters(
        BigInteger      x,
        ElGamalParameters    params)
    {
        super(true, params);

        this.x = x;
    }   

    public BigInteger getX()
    {
        return x;
    }

    protected void finalize()
        throws Throwable
    {
        this.x = null;  // ZEROIZE: clear x pointer on de-allocation
    }
}
