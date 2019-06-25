package org.bouncycastle.jcajce.spec;

import java.security.spec.ECPoint;
import java.security.spec.KeySpec;

/**
 * This class specifies a ECGOST3410-94 public key with its associated parameters.
 */

public class ECGOST3410PublicKeySpec
    implements KeySpec
{
    private final ECPoint w;
    private final GOST3410ParameterSpec<ECDomainParameterSpec> parameters;

    /**
     * Creates a new GOST3410PublicKeySpec with the specified parameter values.
     *
     * @param w the public key.
     */
    public ECGOST3410PublicKeySpec(ECPoint w, GOST3410ParameterSpec<ECDomainParameterSpec> parameters)
    {
        this.w = w;
        this.parameters = parameters;
    }

    /**
     * Returns the public point <code>w</code>.
     *
     * @return the public point <code>w</code>.
     */
    public ECPoint getW()
    {
        return this.w;
    }

    public GOST3410ParameterSpec<ECDomainParameterSpec> getParams()
    {
        return parameters;
    }
}
