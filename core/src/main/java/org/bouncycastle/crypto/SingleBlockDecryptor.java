package org.bouncycastle.crypto;

/**
 * Base interface for a decryptor only able to decrypt a single block of data.
 *
 * @param <T> the parameters type for the decryptor's cipher..
 */
public interface SingleBlockDecryptor<T extends Parameters>
    extends SingleBlockCipher<T>
{
    /**
     * Decrypt a single block of data, returning the result.
     *
     * @param bytes array holding encrypted block.
     * @param offSet offset into bytes where encrypted data starts.
     * @param length the number of bytes of encrypted data in the bytes array.
     * @return a byte array holding the decrypted data.
     *
     * @throws InvalidCipherTextException in the event the data is inappropriate for the cipher implemented.
     */
    byte[] decryptBlock(byte[] bytes, int offSet, int length)
        throws InvalidCipherTextException;
}
