package org.bouncycastle.jcajce.spec;

import java.math.BigInteger;
import java.security.spec.KeySpec;

/**
 * This class specifies a DSTU4145 private key with its associated parameters.
 */

public class DSTU4145PrivateKeySpec
    implements KeySpec
{
    private final BigInteger s;
    private final DSTU4145ParameterSpec parameters;

    /**
     * Creates a new GOST3410PrivateKeySpec with the specified parameter values.
     *
     * @param s the private key.
     */
    public DSTU4145PrivateKeySpec(BigInteger s, DSTU4145ParameterSpec parameters)
    {
        this.s = s;
        this.parameters = parameters;
    }


    public DSTU4145ParameterSpec getParams()
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
