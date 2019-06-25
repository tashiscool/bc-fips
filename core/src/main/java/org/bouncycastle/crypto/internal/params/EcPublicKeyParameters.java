/***************************************************************/
/******    DO NOT EDIT THIS CLASS bc-java SOURCE FILE     ******/
/***************************************************************/
package org.bouncycastle.crypto.internal.params;

import org.bouncycastle.math.ec.ECPoint;

public class EcPublicKeyParameters
    extends EcKeyParameters
{
    ECPoint Q;

    public EcPublicKeyParameters(
        ECPoint             Q,
        EcDomainParameters params)
    {
        super(false, params);
        this.Q = Q.normalize();
    }

    public ECPoint getQ()
    {
        return Q;
    }
}
