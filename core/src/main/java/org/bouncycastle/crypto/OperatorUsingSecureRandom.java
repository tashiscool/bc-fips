package org.bouncycastle.crypto;

import java.security.SecureRandom;

/**
 * Interface allowing an operator to be created with a particular SecureRandom.
 *
 * @param <T> the operator returned.
 */
public interface OperatorUsingSecureRandom<T>
{
    /**
     * Create a version of T using the SecureRandom random.
     *
     * @param random the SecureRandom to use.
     * @return a new version of T using random.
     */
    T withSecureRandom(SecureRandom random);
}
