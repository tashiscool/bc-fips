package org.bouncycastle.crypto;

/**
 * Interface describing an encapsulated secret extractor. These represent algorithms such as KTS.
 *
 * @param <T> the type for the parameters used by this extractor.
 */
public interface EncapsulatedSecretExtractor<T extends Parameters>
{
    /**
     * Return the parameters being used by this extractor.
     *
     * @return the extractor parameters.
     */
    T getParameters();

    /**
     * Open up an encapsulation and extract the key material it contains.
     *
     * @param encapsulation the data that is carrying the secret.
     * @param offset the offset into encapsulation that the actual encapsulation starts at.
     * @param length the length of the encapsulation stored in the encapsulation array.
     * @return the secret and the data representing the encapsulation.
     * @throws InvalidCipherTextException if there is an issue opening the encapsulation.
     */
    SecretWithEncapsulation extractSecret(final byte[] encapsulation, final int offset, final int length)
        throws InvalidCipherTextException;
}
