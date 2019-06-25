package org.bouncycastle.jcajce.spec;

import java.math.BigInteger;
import java.security.spec.KeySpec;

/**
 * This class specifies a GOST3410-94 public key with its associated parameters.
 */

public class GOST3410PublicKeySpec
    implements KeySpec
{
    private final BigInteger y;
    private final GOST3410ParameterSpec<GOST3410DomainParameterSpec> parameters;

    /**
     * Creates a new GOST3410PublicKeySpec with the specified parameter values.
     *
     * @param y the public key.
     */
    public GOST3410PublicKeySpec(BigInteger y, GOST3410ParameterSpec<GOST3410DomainParameterSpec> parameters)
    {
        this.y = y;
        this.parameters = parameters;
    }

    /**
     * Returns the public key <code>y</code>.
     *
     * @return the public key <code>y</code>.
     */
    public BigInteger getY()
    {
        return this.y;
    }

    public GOST3410ParameterSpec<GOST3410DomainParameterSpec> getParams()
    {
        return parameters;
    }
}
