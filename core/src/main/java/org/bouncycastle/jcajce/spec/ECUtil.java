package org.bouncycastle.jcajce.spec;

import java.math.BigInteger;
import java.security.spec.ECField;
import java.security.spec.ECFieldF2m;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.crypto.asymmetric.ECDomainParameters;
import org.bouncycastle.crypto.asymmetric.ECDomainParametersIndex;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.field.FiniteField;
import org.bouncycastle.math.field.Polynomial;
import org.bouncycastle.math.field.PolynomialExtensionField;
import org.bouncycastle.util.Arrays;

class ECUtil
{
    private static Map customCurves = new HashMap();

    static
    {
        Set<ASN1ObjectIdentifier> oids = new HashSet<ASN1ObjectIdentifier>();

        Enumeration e = ECNamedCurveTable.getNames();
        while (e.hasMoreElements())
        {
            String name = (String)e.nextElement();

            oids.add(ECNamedCurveTable.getOID(name));
        }

        for (ASN1ObjectIdentifier curveOID : oids)
        {
            ECDomainParameters domainParameters = ECDomainParametersIndex.lookupDomainParameters(curveOID);

            customCurves.put(ECNamedCurveTable.getByOID(curveOID).getCurve(), domainParameters.getCurve());
        }
    }

    static ECCurve convertCurve(
        EllipticCurve ec, BigInteger order, int cofactor)
    {
        ECField field = ec.getField();
        BigInteger a = ec.getA();
        BigInteger b = ec.getB();

        if (field instanceof ECFieldFp)
        {
            ECCurve.Fp curve = new ECCurve.Fp(((ECFieldFp)field).getP(), a, b, order, BigInteger.valueOf(cofactor));

            if (customCurves.containsKey(curve))
            {
                return (ECCurve)customCurves.get(curve);
            }

            return curve;
        }
        else
        {
            ECFieldF2m fieldF2m = (ECFieldF2m)field;
            int m = fieldF2m.getM();
            int ks[] = convertMidTerms(fieldF2m.getMidTermsOfReductionPolynomial());
            return new ECCurve.F2m(m, ks[0], ks[1], ks[2], a, b, order, BigInteger.valueOf(cofactor));
        }
    }

    public static EllipticCurve convertCurve(
        ECCurve curve,
        byte[]  seed)
    {
        ECField field = convertField(curve.getField());
        BigInteger a = curve.getA().toBigInteger(), b = curve.getB().toBigInteger();

        // TODO: the Sun EC implementation doesn't currently handle the seed properly
        // so at the moment it's set to null. Should probably look at making this configurable
        return new EllipticCurve(field, a, b, null);
    }

    public static ECField convertField(FiniteField field)
    {
        if (ECAlgorithms.isFpField(field))
        {
            return new ECFieldFp(field.getCharacteristic());
        }
        else //if (ECAlgorithms.isF2mField(curveField))
        {
            Polynomial poly = ((PolynomialExtensionField)field).getMinimalPolynomial();
            int[] exponents = poly.getExponentsPresent();
            int[] ks = Arrays.reverse(Arrays.copyOfRange(exponents, 1, exponents.length - 1));
            return new ECFieldF2m(poly.getDegree(), ks);
        }
    }

    public static ECParameterSpec convertToSpec(
        ECDomainParameters domainParameters)
    {
        return new ECParameterSpec(
            convertCurve(domainParameters.getCurve(), null),  // JDK 1.5 has trouble with this if it's not null...
            new ECPoint(
                domainParameters.getG().getAffineXCoord().toBigInteger(),
                domainParameters.getG().getAffineYCoord().toBigInteger()),
            domainParameters.getN(),
            domainParameters.getH().intValue());
    }

    public static ECDomainParameters convertFromSpec(
        ECParameterSpec ecSpec)
    {
        ECCurve curve = convertCurve(ecSpec.getCurve(), ecSpec.getOrder(), ecSpec.getCofactor());

        return new ECDomainParameters(
            curve,
            convertPoint(curve, ecSpec.getGenerator()),
            ecSpec.getOrder(),
            BigInteger.valueOf(ecSpec.getCofactor()),
            ecSpec.getCurve().getSeed());
    }

    public static org.bouncycastle.math.ec.ECPoint convertPoint(
        ECCurve curve,
        ECPoint point)
    {
        return curve.validatePoint(point.getAffineX(), point.getAffineY());
    }

    /**
     * Returns a sorted array of middle terms of the reduction polynomial.
     * @param k The unsorted array of middle terms of the reduction polynomial
     * of length 1 or 3.
     * @return the sorted array of middle terms of the reduction polynomial.
     * This array always has length 3.
     */
    private static int[] convertMidTerms(
        int[] k)
    {
        int[] res = new int[3];

        if (k.length == 1)
        {
            res[0] = k[0];
        }
        else
        {
            if (k.length != 3)
            {
                throw new IllegalArgumentException("Only Trinomials and pentanomials supported");
            }

            if (k[0] < k[1] && k[0] < k[2])
            {
                res[0] = k[0];
                if (k[1] < k[2])
                {
                    res[1] = k[1];
                    res[2] = k[2];
                }
                else
                {
                    res[1] = k[2];
                    res[2] = k[1];
                }
            }
            else if (k[1] < k[2])
            {
                res[0] = k[1];
                if (k[0] < k[2])
                {
                    res[1] = k[0];
                    res[2] = k[2];
                }
                else
                {
                    res[1] = k[2];
                    res[2] = k[0];
                }
            }
            else
            {
                res[0] = k[2];
                if (k[0] < k[1])
                {
                    res[1] = k[0];
                    res[2] = k[1];
                }
                else
                {
                    res[1] = k[1];
                    res[2] = k[0];
                }
            }
        }

        return res;
    }
}
