package org.bouncycastle.crypto;

/**
 * Base interface for keys.
 */
public interface Key
{
    /**
     * The algorithm the key is for.
     *
     * @return the key's algorithm.
     */
    Algorithm getAlgorithm();

    /**
     * Return true if o is an equivalent key to this.
     *
     * @param o object to compare to.
     * @return true if o is the same or equivalent key, false otherwise.
     */
    boolean equals(Object o);

    /**
     * Return the hashCode for the key.
     *
     * @return the key's hashCode.
     */
    int hashCode();
}
