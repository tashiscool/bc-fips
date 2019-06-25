package org.bouncycastle.crypto.general;

import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.Parameters;

/**
 * The base class for parameter classes for non-FIPS algorithms.
 *
 * @param <T> the algorithm associated with this parameter set (may actually be a FIPS one).
 */
public class GeneralParameters<T extends Algorithm>
    implements Parameters
{
    private final T algorithm;

    GeneralParameters(T algorithm)
    {
        this.algorithm = algorithm;
    }

    /**
     * Return the algorithm these parameters are associated with.
     *
     * @return the algorithm these parameters are for.
     */
    public T getAlgorithm()
    {
        return algorithm;
    }
}
