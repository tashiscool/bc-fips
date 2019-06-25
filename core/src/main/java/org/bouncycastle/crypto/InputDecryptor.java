package org.bouncycastle.crypto;

import java.io.InputStream;

/**
 * Base interface for an input consuming Decryptor.
 *
 * @param <T> the parameters type for the decryptor.
 */
public interface InputDecryptor<T>
{
    /**
     * Return the parameters for this decryptor.
     *
     * @return the decryptor's parameters.
     */
    T getParameters();

    /**
     * Return a stream which will decrypt what it reads from the stream in and pass it through.
     *
     * @param in the source of encrypted data..
     * @return a stream which produces decrypted data based on bytes read from in..
     */
    InputStream getDecryptingStream(InputStream in);
}
