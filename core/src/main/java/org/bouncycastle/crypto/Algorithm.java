package org.bouncycastle.crypto;

import java.io.Serializable;

/**
 * Base interface for an algorithm descriptor.
 */
public interface Algorithm
    extends Serializable
{
    /**
     * Return a string representation of the algorithm.
     *
     * @return the algorithm name.
     */
    String getName();

    /**
     * Returns true if this algorithm requires additional parameter fields, false otherwise.
     *
     * @return true if algorithm requires parameters.
     */
    boolean requiresAlgorithmParameters();

    /**
     * Object equals method.
     * @param o the object to be checked for equality.
     * @return true if o is equal to this, false otherwise.
     */
    boolean equals(Object o);

    /**
     * Object hashCode method.
     *
     * @return calculated hash code for this object.
     */
    int hashCode();
}
