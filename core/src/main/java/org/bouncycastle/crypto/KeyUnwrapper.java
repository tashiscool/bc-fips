package org.bouncycastle.crypto;

/**
 * Base interface for a key un-wrapper.
 *
 * @param <T> the parameter type for the un-wrapper.
 */
public interface KeyUnwrapper<T extends Parameters>
{
    /**
     * Return the parameters for this un-wrapper.
     *
     * @return the un-wrapper's parameters.
     */
    T getParameters();

    /**
     * Return the unwrapped byte encoding of a key.
     *
     * @param in input data array.
     * @param inOff  offset into data array wrapped key starts at.
     * @param inLen  length of wrapped key data.
     * @return the unwrapped byte encoding of the key.
     * @throws InvalidWrappingException if the wrapping cannot be processed.
     */
    byte[] unwrap(byte[] in, int inOff, int inLen)
        throws InvalidWrappingException;
}
