package org.bouncycastle.jcajce.provider;

import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPrivateKeySpec;
import javax.crypto.spec.DHPublicKeySpec;

import org.bouncycastle.crypto.asymmetric.DHDomainParameters;
import org.bouncycastle.jcajce.spec.DHDomainParameterSpec;
import org.bouncycastle.jcajce.spec.DHExtendedPrivateKeySpec;
import org.bouncycastle.jcajce.spec.DHExtendedPublicKeySpec;

class DHUtils
{
    static final int MIN_FIPS_SIZE = 2048;

    static DHDomainParameters extractParams(DHParameterSpec params)
    {
        if (params instanceof DHDomainParameterSpec)
        {
            DHDomainParameterSpec dSpec = (DHDomainParameterSpec)params;

            return new DHDomainParameters(dSpec.getP(), dSpec.getQ(), dSpec.getG(), 0, dSpec.getL(), dSpec.getJ(), dSpec.getValidationParameters());
        }
        return new DHDomainParameters(params.getP(), null, params.getG(), params.getL());
    }

    static DHDomainParameters extractParams(DHPublicKeySpec params)
    {
        if (params instanceof DHExtendedPublicKeySpec)
        {
            return extractParams(((DHExtendedPublicKeySpec)params).getParams());
        }

        return new DHDomainParameters(params.getP(), params.getG());
    }

    static DHDomainParameters extractParams(DHPrivateKeySpec params)
    {
        if (params instanceof DHExtendedPrivateKeySpec)
        {
            return extractParams(((DHExtendedPrivateKeySpec)params).getParams());
        }

        return new DHDomainParameters(params.getP(), params.getG());
    }

    static DHParameterSpec convertParams(DHDomainParameters domainParameters)
    {
        return new DHDomainParameterSpec(domainParameters);
    }
}
