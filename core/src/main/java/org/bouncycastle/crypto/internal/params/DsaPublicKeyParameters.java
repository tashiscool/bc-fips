/***************************************************************/
/******    DO NOT EDIT THIS CLASS bc-java SOURCE FILE     ******/
/***************************************************************/
package org.bouncycastle.crypto.internal.params;

import java.math.BigInteger;

public class DsaPublicKeyParameters
    extends DsaKeyParameters
{
    private BigInteger      y;

    public DsaPublicKeyParameters(
        BigInteger      y,
        DsaParameters   params)
    {
        super(false, params);

        this.y = y;
    }   

    public BigInteger getY()
    {
        return y;
    }
}
