package org.bouncycastle.crypto.asymmetric;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ua.DSTU4145NamedCurves;
import org.bouncycastle.asn1.ua.DSTU4145Params;
import org.bouncycastle.util.Arrays;

/**
 * Container class for DSTU4145 parameters.
 */
public final class DSTU4145Parameters
{
    private final byte[]             dke;
    private final ECDomainParameters domainParameters;

    public DSTU4145Parameters(ASN1ObjectIdentifier domainParameters)
    {
        this(domainParameters, DSTU4145Params.getDefaultDKE());
    }

    public DSTU4145Parameters(ASN1ObjectIdentifier domainParameters, byte[] dke)
    {
        this(getDomainParameters(domainParameters), dke);
    }

    public DSTU4145Parameters(ECDomainParameters domainParameters)
    {
        this(domainParameters, DSTU4145Params.getDefaultDKE());
    }

    public DSTU4145Parameters(ECDomainParameters domainParameters, byte[] dke)
    {
        this.domainParameters = domainParameters;
        this.dke = Arrays.clone(dke);
    }

    public byte[] getDKE()
    {
        return Arrays.clone(dke);
    }

    public ECDomainParameters getDomainParameters()
    {
        return domainParameters;
    }

    private static ECDomainParameters getDomainParameters(ASN1ObjectIdentifier oid)
    {
        ECDomainParameters ecParams = DSTU4145NamedCurves.getByOID(oid);

        return new NamedECDomainParameters(oid, ecParams.getCurve(), ecParams.getG(), ecParams.getN(), ecParams.getH());
    }

    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }

        if (o instanceof DSTU4145Parameters)
        {
            return this.domainParameters.equals(((DSTU4145Parameters)o).domainParameters) && Arrays.areEqual(this.dke, ((DSTU4145Parameters)o).dke);
        }

        return false;
    }

    public int hashCode()
    {
        return domainParameters.hashCode() + 37 * Arrays.hashCode(this.dke);
    }
}
