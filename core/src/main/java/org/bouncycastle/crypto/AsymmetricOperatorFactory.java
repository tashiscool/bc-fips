package org.bouncycastle.crypto;

/**
 * Interface describing a factory that creates encryptors and decryptors based on public key cryptography.
 *
 * @param <T> the type for the parameters for the operator made by this factory.
 */
public interface AsymmetricOperatorFactory<T extends Parameters>
{
    /**
     * Create a block encryptor for the passed in key and parameter set.
     *
     * @param key the key to be used in the encryptor.
     * @param parameter the parameter set for the encryptor.
     * @return an initialised block encryptor for the passed in arguments.
     */
    SingleBlockEncryptor<T> createBlockEncryptor(AsymmetricKey key, T parameter);

    /**
     * Create a block decryptor for the passed in key and parameter set.
     *
     * @param key the key to be used in the decryptor.
     * @param parameter the parameter set for the decryptor.
     * @return an initialised block decryptor for the passed in arguments.
     */
    SingleBlockDecryptor<T> createBlockDecryptor(AsymmetricKey key, T parameter);
}
