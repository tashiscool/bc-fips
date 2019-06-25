package org.bouncycastle.jcajce.provider;

import java.security.interfaces.DSAParams;
import java.security.spec.DSAParameterSpec;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.DSAPublicKeySpec;

import org.bouncycastle.crypto.asymmetric.DSADomainParameters;

class DSAUtils
{
    static DSADomainParameters extractParams(DSAParams params)
    {
        return new DSADomainParameters(params.getP(), params.getQ(), params.getG());
    }

    static DSADomainParameters extractParams(DSAPublicKeySpec params)
    {
        return new DSADomainParameters(params.getP(), params.getQ(), params.getG());
    }

    static DSADomainParameters extractParams(DSAPrivateKeySpec params)
    {
        return new DSADomainParameters(params.getP(), params.getQ(), params.getG());
    }

    static DSAParams convertParams(DSADomainParameters domainParameters)
    {
        return new DSAParameterSpec(domainParameters.getP(), domainParameters.getQ(), domainParameters.getG());
    }
}
