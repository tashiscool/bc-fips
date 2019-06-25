package org.bouncycastle.crypto;

import java.io.IOException;

/**
 * Returned stream for writing data for encryption/decryption.
 */
public abstract class CipherOutputStream
    extends UpdateOutputStream
{
    /**
     * Closes this output stream and releases any system resources
     * associated with this stream.
     * <p>
     * This method invokes the <code>doFinal</code> method of the encapsulated
     * cipher object, which causes any bytes buffered by the encapsulated
     * cipher to be processed. The result is written out by calling the
     * <code>flush</code> method of this output stream.
     * <p>
     * This method resets the encapsulated cipher object to its initial state
     * and does not call <code>close</code> method of the underlying output
     * stream.
     *
     * @throws java.io.IOException if an I/O error occurs.
     * @throws InvalidCipherTextException if the data written to this stream was invalid cipher text
     * (e.g. the cipher is an AEAD cipher and the cipher text tag check fails).
     */
    public abstract void close()
        throws IOException;
}
