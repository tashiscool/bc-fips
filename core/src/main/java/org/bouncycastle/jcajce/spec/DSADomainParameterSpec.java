package org.bouncycastle.jcajce.spec;

import java.math.BigInteger;
import java.security.spec.DSAParameterSpec;

import org.bouncycastle.crypto.asymmetric.DSADomainParameters;
import org.bouncycastle.crypto.asymmetric.DSAValidationParameters;

/**
 * Extension class for DSAParameterSpec that wraps a DSADomainParameters object and provides the validation
 * parameters if available.
 */
public class DSADomainParameterSpec
    extends DSAParameterSpec
{
    private final DSAValidationParameters validationParameters;

    /**
     * Base constructor - use the values in an existing set of domain parameters.
     *
     * @param domainParameters the DSA domain parameters to wrap.
     */
    public DSADomainParameterSpec(DSADomainParameters domainParameters)
    {
        this(domainParameters.getP(), domainParameters.getQ(), domainParameters.getG(), domainParameters.getValidationParameters());
    }

    /**
     * Creates a new DSAParameterSpec with the specified parameter values.
     *
     * @param p the prime.
     * @param q the sub-prime.
     * @param g the base.
     */
    public DSADomainParameterSpec(BigInteger p, BigInteger q, BigInteger g)
    {
        this(p, q, g, null);
    }

    /**
     * Creates a new DSAParameterSpec with the specified parameter values.
     *
     * @param p the prime.
     * @param q the sub-prime.
     * @param g the base.
     * @param validationParameters the validation parameters (may be null if not available)
     */
    public DSADomainParameterSpec(BigInteger p, BigInteger q, BigInteger g, DSAValidationParameters validationParameters)
    {
        super(p, q, g);

        this.validationParameters = validationParameters;
    }

    /**
     * Return the validation parameters associated with this parameter spec if available.
     *
     * @return the validation parameters, null if not available.
     */
    public DSAValidationParameters getValidationParameters()
    {
        return validationParameters;
    }

    /**
     * Return the DSADomainParameters object we also represent.
     *
     * @return a DSADomainParameters.
     */
    public DSADomainParameters getDomainParameters()
    {
        return new DSADomainParameters(getP(), getQ(), getG(), validationParameters);
    }

}
