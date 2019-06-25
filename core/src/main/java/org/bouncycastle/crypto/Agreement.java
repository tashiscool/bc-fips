package org.bouncycastle.crypto;

/**
 * Basic interface for key agreement implementations.
 * @param <T> the parameters class for the particular version.
 */
public interface Agreement<T extends Parameters>
{
    /**
     * Return the parameters being used by this agreement.
     *
     * @return the key agreement parameters.
     */
    T getParameters();

    /**
     * Calculate the agreement using the passed in public key.
     *
     * @param key the public key of the other party.
     * @return the agreement value.
     */
    byte[] calculate(AsymmetricPublicKey key);
}
