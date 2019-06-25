package org.bouncycastle.jcajce.provider;

import org.bouncycastle.crypto.asymmetric.DSTU4145Parameters;
import org.bouncycastle.jcajce.spec.DSTU4145ParameterSpec;
import org.bouncycastle.jcajce.spec.ECDomainParameterSpec;

class DSTU4145Util
{
    static DSTU4145Parameters convertToECParams(DSTU4145ParameterSpec params)
    {
        return new DSTU4145Parameters(new ECDomainParameterSpec(params).getDomainParameters(), params.getDKE());
    }

    public static DSTU4145ParameterSpec convertToECSpec(DSTU4145Parameters parameters)
    {
        return new DSTU4145ParameterSpec(parameters.getDomainParameters());
    }
}
