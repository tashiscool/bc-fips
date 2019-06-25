package org.bouncycastle.crypto;

/**
 * Interface describing an operator factory that creates operators for doing
 * encryption and decryption using symmetric ciphers.
 *
 * @param <T> the parameters type for the operators the factory creates.
 */
public interface SymmetricOperatorFactory<T extends Parameters>
{
    /**
     * Return an encryptor that operates on an output stream.
     *
     * @param key the key to initialize the encryptor with.
     * @param parameter the parameters to use to initialize the encryptor.
     * @return an OutputEncryptor
     */
    OutputEncryptor<T> createOutputEncryptor(SymmetricKey key, T parameter);

    /**
     * Return a decryptor that operates on an output stream.
     *
     * @param key the key to initialize the encryptor with.
     * @param parameter the parameters to use to initialize the encryptor.
     * @return an OutputDecryptor.
     */
    OutputDecryptor<T> createOutputDecryptor(SymmetricKey key, T parameter);

    /**
     * Return a decryptor that operates on an input stream.
     *
     * @param key the key to initialize the encryptor with.
     * @param parameter the parameters to use to initialize the encryptor.
     * @return an InputDecryptor.
     */
    InputDecryptor<T> createInputDecryptor(SymmetricKey key, T parameter);
}
