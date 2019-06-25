package org.bouncycastle.crypto;

/**
 * Base interface for a cipher which produces encrypted/decrypted output.
 *
 * @param <T> the parameters type for the output cipher.
 */
public interface OutputCipher<T extends Parameters>
{
    /**
     * Return the parameters for this cipher.
     *
     * @return the cipher's parameters.
     */
    T getParameters();

    /**
     * Return the size of the output buffer required for a write() plus a
     * close() with the write() being passed inputLen bytes.
     * <p>
     * The returned size may be dependent on the initialisation of this cipher
     * and may not be accurate once subsequent input data is processed as the cipher may
     * add, add or remove padding, as it sees fit.
     * </p>
     * @param inputLen the length of the input.
     * @return the space required to accommodate a call to processBytes and doFinal
     * with inputLen bytes of input.
     */
    int getMaxOutputSize(int inputLen);

    /**
     * Return the size of the output buffer required for a write() with the write() being
     * passed inputLen bytes and just updating the cipher output.
     * <p>
     * The returned size may be dependent on the state of this cipher.
     * </p>
     * @param inputLen the length of the input.
     * @return the space required to accommodate a call to processBytes with inputLen bytes of input.
     */
    int getUpdateOutputSize(int inputLen);
}
