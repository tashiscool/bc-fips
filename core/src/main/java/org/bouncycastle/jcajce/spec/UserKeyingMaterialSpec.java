package org.bouncycastle.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.util.Arrays;

/**
 * User keying material for the KDF used in key agreement algorithms.
 */
public class UserKeyingMaterialSpec
    implements AlgorithmParameterSpec
{
    private final byte[] userKeyingMaterial;

    /**
     * Base constructor.
     *
     * @param userKeyingMaterial the bytes to be mixed in to the key agreement's KDF.
     */
    public UserKeyingMaterialSpec(byte[] userKeyingMaterial)
    {
        this.userKeyingMaterial = Arrays.clone(userKeyingMaterial);
    }

    /**
     * Return a copy of the key material in this object.
     *
     * @return the user keying material.
     */
    public byte[] getUserKeyingMaterial()
    {
        return Arrays.clone(userKeyingMaterial);
    }
}
