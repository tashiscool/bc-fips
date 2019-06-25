package org.bouncycastle.crypto;

/**
 * Base interface for a encryptor only able to encrypt a single block of data.
 *
 * @param <T> the parameters type for the encryptor's cipher..
 */
public interface SingleBlockEncryptor<T extends Parameters>
    extends SingleBlockCipher<T>
{
    /**
     * Encrypt a single block of data, returning the result.
     *
     * @param bytes array holding the data to be encrypted.
     * @param offSet offset into bytes where the data starts.
     * @param length the number of bytes of data in the bytes array.
     * @return a byte array holding the encrypted result.
     * @throws PlainInputProcessingException if there is an issue processing the input provided.
     */
    byte[] encryptBlock(byte[] bytes, int offSet, int length)
        throws PlainInputProcessingException;
}
