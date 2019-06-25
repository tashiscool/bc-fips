package org.bouncycastle.crypto;

import java.io.OutputStream;

/**
 * Base interface for an output producing Encryptor.
 *
 * @param <T> the parameters type for the encryptor.
 */
public interface OutputEncryptor<T extends Parameters>
    extends OutputCipher<T>
{
    /**
     * Return a stream which will encrypt it's input writing the results to out.
     *
     * @param out the output stream to collect the encrypted data in.
     * @return a stream for writing the original plain-text data.
     */
    CipherOutputStream getEncryptingStream(OutputStream out);
}
