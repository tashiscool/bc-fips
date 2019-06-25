/***************************************************************/
/******    DO NOT EDIT THIS CLASS bc-java SOURCE FILE     ******/
/***************************************************************/
package org.bouncycastle.crypto.internal.params;

import java.math.BigInteger;

public class EcPrivateKeyParameters
    extends EcKeyParameters
{
    BigInteger d;

    public EcPrivateKeyParameters(
        BigInteger          d,
        EcDomainParameters params)
    {
        super(true, params);
        this.d = d;
    }

    public BigInteger getD()
    {
        return d;
    }
}
