package org.bouncycastle.crypto;

/**
 * Base interface for operator parameters.
 */
public interface Parameters
{
    /**
     * Return the algorithm these parameters are associated with.
     *
     * @return the algorithm these parameters are for.
     */
    Algorithm getAlgorithm();
}
