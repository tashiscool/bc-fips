package org.bouncycastle.crypto.asymmetric;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

/**
 * EC domain parameters associated with a specific object identifier.
 */
public class NamedECDomainParameters
    extends ECDomainParameters
{
    private ASN1ObjectIdentifier id;

    /**
     * Constructor that assumes the co-factor h is 1.
     *
     * @param id the object identifier that represents these parameters.
     * @param curve the curve for these domain parameters.
     * @param G the base point G for the domain parameters.
     * @param n the order for the domain parameters.
     */
    public NamedECDomainParameters(
        ASN1ObjectIdentifier id,
        ECCurve curve,
        ECPoint G,
        BigInteger n)
    {
        this(id, curve, G, n, BigInteger.ONE, null);
    }

    /**
     * Constructor with explicit co-factor.
     *
     * @param id the object identifier that represents these parameters.
     * @param curve the curve for these domain parameters.
     * @param G the base point G for the domain parameters.
     * @param n the order for the domain parameters.
     * @param h the co-factor.
     */
    public NamedECDomainParameters(
        ASN1ObjectIdentifier id,
        ECCurve curve,
        ECPoint G,
        BigInteger n,
        BigInteger h)
    {
        this(id, curve, G, n, h, null);
    }

    /**
     * Constructor with explicit co-factor and generation seed.
     *
     * @param id the object identifier that represents these parameters.
     * @param curve the curve for these domain parameters.
     * @param G the base point G for the domain parameters.
     * @param n the order for the domain parameters.
     * @param h the co-factor.
     * @param seed the seed value used to generate the domain parameters.
     */
    public NamedECDomainParameters(
        ASN1ObjectIdentifier id,
        ECCurve curve,
        ECPoint G,
        BigInteger n,
        BigInteger h,
        byte[] seed)
    {
        super(curve, G, n, h, seed);
        this.id = id;
    }

    /**
     * Return object identifier that identifies these parameters.
     *
     * @return the OID that names this parameter set.
     */
    public ASN1ObjectIdentifier getID()
    {
        return id;
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
