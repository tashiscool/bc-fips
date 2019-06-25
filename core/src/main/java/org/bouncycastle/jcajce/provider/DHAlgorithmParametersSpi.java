package org.bouncycastle.jcajce.provider;

import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.spec.DHParameterSpec;

import org.bouncycastle.jcajce.spec.DHDomainParameterSpec;

abstract class DHAlgorithmParametersSpi
    extends X509AlgorithmParameters
{
    private final String algorithm;

    protected DHDomainParameterSpec currentSpec;

    DHAlgorithmParametersSpi(String algorithm)
    {
        this.algorithm = algorithm;
    }

    protected void engineInit(
        AlgorithmParameterSpec paramSpec)
        throws InvalidParameterSpecException
    {
        if (paramSpec instanceof DHParameterSpec)
        {
            DHParameterSpec s = (DHParameterSpec)paramSpec;

            this.currentSpec = new DHDomainParameterSpec(s.getP(), null, s.getG(), s.getL());
        }
        else if (paramSpec instanceof DHDomainParameterSpec)
        {
            this.currentSpec = (DHDomainParameterSpec)paramSpec;
        }
        else
        {
            throw new InvalidParameterSpecException("DHParameterSpec/DHDomainParameterSpec required to initialize " + algorithm + " AlgorithmParameters");
        }
    }

    protected final AlgorithmParameterSpec localEngineGetParameterSpec(
        Class paramSpec)
        throws InvalidParameterSpecException
    {
        if (paramSpec == DHParameterSpec.class)
        {
            return new DHParameterSpec(currentSpec.getP(), currentSpec.getG(), currentSpec.getL());
        }
        if (paramSpec == DHDomainParameterSpec.class || paramSpec == AlgorithmParameterSpec.class)
        {
            return currentSpec;
        }

        throw new InvalidParameterSpecException("AlgorithmParameterSpec not recognized: " + paramSpec.getName());
    }
}
