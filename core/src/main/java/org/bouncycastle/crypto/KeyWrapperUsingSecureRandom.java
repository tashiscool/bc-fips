package org.bouncycastle.crypto;

import java.security.SecureRandom;

/**
 * Interface describing a KeyWrapper which also requires a SecureRandom as part of its configuration.
 *
 * @param <T> the parameter type for the wrapper.
 */
public interface KeyWrapperUsingSecureRandom<T extends Parameters>
    extends KeyWrapper<T>, OperatorUsingSecureRandom<KeyWrapperUsingSecureRandom<T>>
{
    /**
     * Return a variant of this signer using the passed in random as its source of randomness.
     *
     * @param random the SecureRandom to use.
     * @return a signer which will use random where random data is required.
     */
    KeyWrapperUsingSecureRandom<T> withSecureRandom(SecureRandom random);
}
