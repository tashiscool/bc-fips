package org.bouncycastle.jcajce.spec;

import java.math.BigInteger;
import java.security.spec.KeySpec;

/**
 * This class specifies a ECGOST3410-94 private key with its associated parameters.
 */

public class ECGOST3410PrivateKeySpec
    implements KeySpec
{
    private final BigInteger s;
    private final GOST3410ParameterSpec<ECDomainParameterSpec> parameters;

    /**
     * Creates a new GOST3410PrivateKeySpec with the specified parameter values.
     *
     * @param s the private key.
     */
    public ECGOST3410PrivateKeySpec(BigInteger s, GOST3410ParameterSpec<ECDomainParameterSpec> parameters)
    {
        this.s = s;
        this.parameters = parameters;
    }


    public GOST3410ParameterSpec<ECDomainParameterSpec> getParams()
    {
        return parameters;
    }

    /**
     * Returns the private key value <code>s</code>.
     * @return the private key <code>s</code>.
     */
    public BigInteger getS()
    {
        return s;
    }
}
