package org.bouncycastle.crypto;

import java.security.SecureRandom;

/**
 * Interface describing a KeyUnwrapper which also requires a SecureRandom as part of its configuration.
 *
 * @param <T> the parameter type for the un-wrapper.
 */
public interface KeyUnwrapperUsingSecureRandom<T extends Parameters>
    extends KeyUnwrapper<T>, OperatorUsingSecureRandom<KeyUnwrapperUsingSecureRandom<T>>
{
    /**
     * Return a variant of this signer using the passed in random as its source of randomness.
     *
     * @param random the SecureRandom to use.
     * @return a signer which will use random where random data is required.
     */
    KeyUnwrapperUsingSecureRandom<T> withSecureRandom(SecureRandom random);
}
