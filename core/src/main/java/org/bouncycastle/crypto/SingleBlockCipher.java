package org.bouncycastle.crypto;

/**
 * Base interface for a cipher only able to handle a single block of data.
 *
 * @param <T> the parameters type for the cipher implemented.
 */
public interface SingleBlockCipher<T extends Parameters>
{
    /**
     * Return the parameters for this single block cipher.
     *
     * @return the cipher's parameters.
     */
    T getParameters();

    /**
     * Return the maximum size of input this cipher can consume.
     *
     * @return maximum size of input in bytes.
     */
    int getInputSize();

    /**
     * Return the size of the output this cipher will produce.
     *
     * @return size of the output block produced in bytes.
     */
    int getOutputSize();
}
