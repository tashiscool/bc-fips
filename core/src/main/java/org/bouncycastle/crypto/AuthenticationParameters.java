package org.bouncycastle.crypto;

/**
 * Interface that parameters sets associated with MACs should conform to.
 *
 * @param <T> the implementing type for this interface.
 */
public interface AuthenticationParameters<T extends Parameters>
    extends Parameters
{
    /**
     * Return the size of the MAC these parameters are for.
     *
     * @return the MAC size in bits.
     */
    int getMACSizeInBits();

    /**
     * Create a parameter set with the specified MAC size associated with it.
     *
     * @param macSizeInBits bit length of the MAC length.
     * @return the new parameter set.
     */
    T withMACSize(int macSizeInBits);
}
