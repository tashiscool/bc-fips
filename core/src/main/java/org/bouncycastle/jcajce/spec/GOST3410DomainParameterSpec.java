package org.bouncycastle.jcajce.spec;

import java.math.BigInteger;
import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.crypto.asymmetric.GOST3410DomainParameters;

/**
 * ParameterSpec for a GOST 3410-94 key.
 */
public final class GOST3410DomainParameterSpec
    implements AlgorithmParameterSpec
{
    private GOST3410DomainParameters parameters;

    public GOST3410DomainParameterSpec(
        GOST3410DomainParameters parameters)
    {
        this.parameters = parameters;
    }

    public boolean equals(Object o)
    {
        if (o instanceof GOST3410DomainParameterSpec)
        {
            GOST3410DomainParameterSpec other = (GOST3410DomainParameterSpec)o;
            
            return this.parameters.equals(other.parameters);
        }
        
        return false;
    }
    
    public int hashCode()
    {
        return this.parameters.hashCode();
    }

    public int getKeySize()
    {
        return parameters.getKeySize();
    }

    public BigInteger getP()
    {
        return parameters.getP();
    }

    public BigInteger getQ()
    {
        return parameters.getQ();
    }

    public BigInteger getA()
    {
        return parameters.getA();
    }
}
