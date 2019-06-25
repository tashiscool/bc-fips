package org.bouncycastle.crypto;

/**
 * Interface describing a symmetric key generator.
 *
 * @param <T> the parameters type for the key generator.
 */
public interface SymmetricKeyGenerator<T extends SymmetricKey>
{
    /**
     * Return a newly generated symmetric key.
     *
     * @return a new symmetric key.
     */
    T generateKey();
}
