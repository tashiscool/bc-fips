package org.bouncycastle.jcajce.provider;

import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;

import org.bouncycastle.crypto.asymmetric.ECDomainParameters;
import org.bouncycastle.crypto.asymmetric.ECImplicitDomainParameters;
import org.bouncycastle.jcajce.spec.ECDomainParameterSpec;
import org.bouncycastle.jcajce.spec.ECImplicitDomainParameterSpec;
import org.bouncycastle.math.ec.ECCurve;

class ECUtil
{
    public static ECParameterSpec convertToSpec(
        ECDomainParameters domainParameters)
    {
        if (domainParameters instanceof ECImplicitDomainParameters)
        {
            return new ECImplicitDomainParameterSpec((ECImplicitDomainParameters)domainParameters);
        }

        return new ECDomainParameterSpec(domainParameters);
    }

    public static ECDomainParameters convertFromSpec(
        ECParameterSpec ecSpec)
    {
        ECDomainParameters domainParameters = new ECDomainParameterSpec(ecSpec).getDomainParameters();

        if (ecSpec instanceof ECImplicitDomainParameterSpec)
        {
            return new ECImplicitDomainParameters(domainParameters);
        }

        return domainParameters;
    }

    public static org.bouncycastle.math.ec.ECPoint convertPoint(
        ECParameterSpec ecSpec,
        ECPoint point)
    {
        return convertPoint(convertFromSpec(ecSpec).getCurve(), point);
    }

    public static org.bouncycastle.math.ec.ECPoint convertPoint(
        ECCurve curve,
        ECPoint point)
    {
        return curve.validatePoint(point.getAffineX(), point.getAffineY());
    }
}
