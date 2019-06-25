/***************************************************************/
/******    DO NOT EDIT THIS CLASS bc-java SOURCE FILE     ******/
/***************************************************************/
package org.bouncycastle.crypto.internal.params;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

public class EcNamedDomainParameters
    extends EcDomainParameters
{
    private final ASN1ObjectIdentifier name;

    public EcNamedDomainParameters(ASN1ObjectIdentifier name, ECCurve curve, ECPoint G, BigInteger n, BigInteger h, byte[] seed)
    {
        super(curve, G, n, h, seed);

        this.name = name;
    }

    public ASN1ObjectIdentifier getName()
    {
        return name;
    }

    // for the purposes of equality and hashCode we ignore the prescence of the name.
    public boolean equals(Object o)
    {
        return super.equals(o);
    }

    public int hashCode()
    {
        return super.hashCode();
    }
}
