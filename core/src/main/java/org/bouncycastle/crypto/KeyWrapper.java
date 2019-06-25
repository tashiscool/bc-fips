package org.bouncycastle.crypto;

/**
 * Base interface for a key wrapper.
 *
 * @param <T> the parameter type for the wrapper.
 */
public interface KeyWrapper<T extends Parameters>
{
    /**
     * Return the parameters for this wrapper.
     *
     * @return the wrapper's parameters.
     */
    T getParameters();

    /**
     * Return the wrapped version of a key byte encoding.
     *
     * @param in input data array.
     * @param inOff  offset into data array key data starts at.
     * @param inLen  length of key data.
     * @return the wrapped encoding of the key.
     * @throws PlainInputProcessingException if the passed in input cannot be processed.
     */
    byte[] wrap(byte[] in, int inOff, int inLen)
        throws PlainInputProcessingException;
}
