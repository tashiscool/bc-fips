package org.bouncycastle.jcajce.provider;

import org.bouncycastle.crypto.asymmetric.ECDomainParameters;
import org.bouncycastle.crypto.asymmetric.GOST3410DomainParameters;
import org.bouncycastle.crypto.asymmetric.GOST3410Parameters;
import org.bouncycastle.jcajce.spec.ECDomainParameterSpec;
import org.bouncycastle.jcajce.spec.GOST3410DomainParameterSpec;
import org.bouncycastle.jcajce.spec.GOST3410ParameterSpec;

class GOST3410Util
{
    static GOST3410Parameters<GOST3410DomainParameters> convertToParams(GOST3410ParameterSpec<GOST3410DomainParameterSpec> params)
    {
        GOST3410DomainParameterSpec domainSpec = params.getDomainParametersSpec();
        return new GOST3410Parameters<GOST3410DomainParameters>(params.getPublicKeyParamSet(), params.getDigestParamSet(), params.getDigestParamSet(),
            new GOST3410DomainParameters(domainSpec.getKeySize(), domainSpec.getP(), domainSpec.getQ(), domainSpec.getA()));
    }

    static GOST3410Parameters<ECDomainParameters> convertToECParams(GOST3410ParameterSpec<ECDomainParameterSpec> params)
    {
        return new GOST3410Parameters<ECDomainParameters>(params.getPublicKeyParamSet(), params.getDigestParamSet(), params.getDigestParamSet(), ECUtil.convertFromSpec(params.getDomainParametersSpec()));
    }

    public static GOST3410ParameterSpec<ECDomainParameterSpec> convertToECSpec(GOST3410Parameters<ECDomainParameters> parameters)
    {
        return new GOST3410ParameterSpec<ECDomainParameterSpec>(parameters);
    }

    public static GOST3410ParameterSpec<GOST3410DomainParameterSpec> convertToSpec(GOST3410Parameters<GOST3410DomainParameters> parameters)
    {
        return new GOST3410ParameterSpec<GOST3410DomainParameterSpec>(parameters);
    }
}
