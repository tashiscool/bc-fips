package org.bouncycastle.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;

/**
 * Parameter spec to allow keywrapping to be configured to use the inverse function.
 */
public class WrapParameterSpec
    implements AlgorithmParameterSpec
{
    private final boolean useInverseFunction;

    /**
     * Base constructor - specify that a wrapper should, or shouldn't use the inverse function
     * for the cipher in wrapping.
     * <p>
     * By default wrappers do not use the inverse function.
     * </p>
     *
     * @param useInverseFunction true if use inverse, false if not.
     */
    public WrapParameterSpec(boolean useInverseFunction)
    {
        this.useInverseFunction = useInverseFunction;
    }

    /**
     * Return whether or not we specify the inverse function.
     *
     * @return true if requiring inverse function, false otherwise.
     */
    public boolean useInverseFunction()
    {
        return useInverseFunction;
    }
}
