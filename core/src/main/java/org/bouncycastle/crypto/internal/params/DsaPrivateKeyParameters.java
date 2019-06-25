/***************************************************************/
/******    DO NOT EDIT THIS CLASS bc-java SOURCE FILE     ******/
/***************************************************************/
package org.bouncycastle.crypto.internal.params;

import java.math.BigInteger;

public class DsaPrivateKeyParameters
    extends DsaKeyParameters
{
    private BigInteger      x;

    public DsaPrivateKeyParameters(
        BigInteger      x,
        DsaParameters   params)
    {
        super(true, params);

        this.x = x;
    }   

    public BigInteger getX()
    {
        return x;
    }
}
