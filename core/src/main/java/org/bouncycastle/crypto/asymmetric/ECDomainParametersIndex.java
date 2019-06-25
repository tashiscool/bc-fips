package org.bouncycastle.crypto.asymmetric;

import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cryptopro.ECGOST3410NamedCurves;
import org.bouncycastle.asn1.ua.DSTU4145NamedCurves;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;

/**
 * General index for Elliptic Curve parameters.
 */
public class ECDomainParametersIndex
{
    /**
     * Retrieve an EC based domain parameter by OID. A custom curve will be returned if one is available.
     *
     * @param paramOid object identifier for the domain parameters.
     * @return the matching domain parameters if found, null otherwise.
     */
    public static NamedECDomainParameters lookupDomainParameters(ASN1ObjectIdentifier paramOid)
    {
        X9ECParameters rv = CustomNamedCurves.getByOID(paramOid);

        if (rv == null)
        {
            rv = ECNamedCurveTable.getByOID(paramOid);
        }

        if (rv != null)
        {
            return new NamedECDomainParameters(paramOid, rv.getCurve(), rv.getG(), rv.getN(), rv.getH(), rv.getSeed());
        }

        ECDomainParameters ecRV = ECGOST3410NamedCurves.getByOID(paramOid);

        if (ecRV == null)
        {
            ecRV = DSTU4145NamedCurves.getByOID(paramOid);
        }

        if (ecRV != null)
        {
            return new NamedECDomainParameters(paramOid, ecRV.getCurve(), ecRV.getG(), ecRV.getN(), ecRV.getH(), ecRV.getSeed());
        }

        return null;
    }

    /**
     * Retrieve an EC based domain parameter by parameter ID. A custom curve will be returned if one is available.
     *
     * @param paramID identifier for the domain parameters.
     * @return the matching domain parameters if found, null otherwise.
     */
    public static NamedECDomainParameters lookupDomainParameters(ECDomainParametersID paramID)
    {
        X9ECParameters rv = CustomNamedCurves.getByName(paramID.getCurveName());

        if (rv == null)
        {
            rv = ECNamedCurveTable.getByName(paramID.getCurveName());
        }

        if (rv != null)
        {
            return new NamedECDomainParameters(ECNamedCurveTable.getOID(paramID.getCurveName()), rv.getCurve(), rv.getG(), rv.getN(), rv.getH(), rv.getSeed());
        }

        ECDomainParameters ecRV = ECGOST3410NamedCurves.getByName(paramID.getCurveName());

        if (ecRV != null)
        {
            return new NamedECDomainParameters(ECGOST3410NamedCurves.getOID(paramID.getCurveName()), ecRV.getCurve(), ecRV.getG(), ecRV.getN(), ecRV.getH(), ecRV.getSeed());
        }

        return null;
    }

    public static ASN1ObjectIdentifier lookupOID(ECDomainParameters domainParameters)
    {
        for (Enumeration<String> en = (Enumeration<String>)ECNamedCurveTable.getNames(); en.hasMoreElements();)
        {
            final String name = en.nextElement();
            X9ECParameters rv = ECNamedCurveTable.getByName(name);

            if (rv.getN().equals(domainParameters.getN()))
            {
                ECDomainParameters params = lookupDomainParameters(new ECDomainParametersID()
                {
                    public String getCurveName()
                    {
                        return name;
                    }
                });
                if (params.equals(domainParameters))
                {
                    return ECNamedCurveTable.getOID(name);
                }
            }
        }

        return null;
    }
}
