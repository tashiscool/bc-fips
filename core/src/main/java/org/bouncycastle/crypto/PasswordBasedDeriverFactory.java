package org.bouncycastle.crypto;

/**
 * Base interface for a creator of password based key derivers.
 *
 * @param <T> the parameters type for the password based key derivers we produce.
 */
public interface PasswordBasedDeriverFactory<T extends Parameters>
{
    /**
     * Create a deriver appropriate to the passed in parameters.
     *
     * @param parameters the parameter details for the deriver to create.
     * @return a deriver.
     */
    PasswordBasedDeriver<T> createDeriver(T parameters);
}
