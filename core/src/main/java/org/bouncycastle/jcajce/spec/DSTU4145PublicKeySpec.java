package org.bouncycastle.jcajce.spec;

import java.security.spec.ECPoint;
import java.security.spec.KeySpec;

/**
 * This class specifies a DSTU4145 public key with its associated parameters.
 */

public class DSTU4145PublicKeySpec
    implements KeySpec
{
    private final ECPoint w;
    private final DSTU4145ParameterSpec parameters;

    /**
     * Creates a new GOST3410PublicKeySpec with the specified parameter values.
     *
     * @param w the public key.
     */
    public DSTU4145PublicKeySpec(ECPoint w, DSTU4145ParameterSpec parameters)
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

    public DSTU4145ParameterSpec getParams()
    {
        return parameters;
    }
}
