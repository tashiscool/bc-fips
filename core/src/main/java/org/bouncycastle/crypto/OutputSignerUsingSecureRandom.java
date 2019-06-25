package org.bouncycastle.crypto;

import java.security.SecureRandom;

/**
 * Interface for an output signer that can make use of a SecureRandom,
 *
 * @param <T> the parameters type for the signer.
 */
public interface OutputSignerUsingSecureRandom<T extends Parameters>
    extends OutputSigner<T>, OperatorUsingSecureRandom<OutputSignerUsingSecureRandom<T>>
{
    /**
     * Return a variant of this signer using the passed in random as its source of randomness.
     *
     * @param random the SecureRandom to use.
     * @return a signer which will use random where random data is required.
     */
    OutputSignerUsingSecureRandom<T> withSecureRandom(SecureRandom random);
}
