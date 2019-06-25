package org.bouncycastle.crypto;

import java.io.OutputStream;

/**
 * Base interface for an output producing Decryptor.
 *
 * @param <T> the parameters type for the decryptor.
 */
public interface OutputDecryptor<T extends Parameters>
    extends OutputCipher<T>
{
    /**
     * Return a stream which will decrypt it's input writing the results to out.
     *
     * @param out the output stream to collect the decrypted data in.
     * @return a stream for writing the encrypted data.
     */
    CipherOutputStream getDecryptingStream(OutputStream out);
}
