package org.bouncycastle.jcajce.spec;

import java.math.BigInteger;
import java.security.spec.KeySpec;

/**
 * This class specifies a GOST3410-94 private key with its associated parameters.
 */

public class GOST3410PrivateKeySpec
    implements KeySpec
{
    private final BigInteger x;
    private final GOST3410ParameterSpec<GOST3410DomainParameterSpec> parameters;

    /**
     * Creates a new GOST3410PrivateKeySpec with the specified parameter values.
     *
     * @param x the private key.
     */
    public GOST3410PrivateKeySpec(BigInteger x, GOST3410ParameterSpec<GOST3410DomainParameterSpec> parameters)
    {
        this.x = x;
        this.parameters = parameters;
    }

    /**
     * Returns the private key <code>x</code>.
     * @return the private key <code>x</code>.
     */
    public BigInteger getX()
    {
        return this.x;
    }

    public GOST3410ParameterSpec<GOST3410DomainParameterSpec> getParams()
    {
        return parameters;
    }
}
