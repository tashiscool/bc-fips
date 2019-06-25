package org.bouncycastle.crypto;

/**
 * Interface for factories producing encryptor/decryptor objects supporting AEAD modes.
 *
 * @param <T> the type for the parameters for the operator made by this factory.
 */
public interface AEADOperatorFactory<T extends Parameters>
{
    /**
     * Create an object for encrypting output and handling AAD data.
     *
     * @param key the key to use to set up the encryptor.
     * @param parameters any additional parameters required to set up the encryptor.
     *
     * @return an AEAD encryptor which can be used wrap an output stream.
     */
    public OutputAEADEncryptor<T> createOutputAEADEncryptor(SymmetricKey key, T parameters);

    /**
     * Create an object for decrypting output and handling AAD data.
     *
     * @param key the key to use to set up the decryptor.
     * @param parameters any additional parameters required to set up the decryptor.
     *
     * @return an AEAD decryptor which can be used wrap an output stream.
     */
    public OutputAEADDecryptor<T> createOutputAEADDecryptor(SymmetricKey key, T parameters);

    /**
     * Create an object for decrypting input and handling AAD data.
     *
     * @param key the key to use to set up the decryptor.
     * @param parameters any additional parameters required to set up the decryptor.
     *
     * @return an AEAD decryptor which can be used wrap an input stream.
     */
    public InputAEADDecryptor<T> createInputAEADDecryptor(SymmetricKey key, T parameters);
}
