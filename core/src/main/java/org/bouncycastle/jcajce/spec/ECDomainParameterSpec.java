package org.bouncycastle.jcajce.spec;

import java.security.spec.ECParameterSpec;

import org.bouncycastle.crypto.asymmetric.ECDomainParameters;
import org.bouncycastle.crypto.asymmetric.NamedECDomainParameters;

/**
 * Extension class for ECParameterSpec that wraps a ECDomainParameters object or an ECParameterSpec
 */
public class ECDomainParameterSpec
    extends ECParameterSpec
{
    private ECDomainParameters parameters;

    /**
     * Base constructor - wrap an ECDomainParameters.
     *
     * @param parameters the EC domain parameters to be wrapped.
     */
    public ECDomainParameterSpec(
        ECDomainParameters parameters)
    {
        this(parameters, ECUtil.convertToSpec(parameters));
    }

    /**
     * Conversion constructor - wrap an ECParameterSpec
     *
     * @param parameterSpec the EC domain parameter spec to be wrapped.
     */
    public ECDomainParameterSpec(
           ECParameterSpec parameterSpec)
    {
        this(ECUtil.convertFromSpec(parameterSpec), parameterSpec);
    }


    /**
     * Return the ECDomainParameters object we carry.
     *
     * @return the internal ECDomainParameters.
     */
    public ECDomainParameters getDomainParameters()
    {
        return parameters;
    }

    private ECDomainParameterSpec(ECDomainParameters parameters, ECParameterSpec ecParameterSpec)
    {
        super(ecParameterSpec.getCurve(), ecParameterSpec.getGenerator(), ecParameterSpec.getOrder(), ecParameterSpec.getCofactor());

        this.parameters = parameters;
    }

    public boolean equals(Object o)
    {
        if (o instanceof ECDomainParameterSpec)
        {
            ECDomainParameterSpec other = (ECDomainParameterSpec)o;
            
            return this.parameters.equals(other.parameters);
        }

        return false;
    }
    
    public int hashCode()
    {
        return this.parameters.hashCode();
    }

    public String toString()
    {
        if (this.parameters instanceof NamedECDomainParameters)
        {
            return ((NamedECDomainParameters)this.parameters).getID().getId();
        }
        else
        {
            return super.toString();
        }
    }
}
