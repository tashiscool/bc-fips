package org.bouncycastle.crypto;

import java.security.SecureRandom;

/**
 * Interface for a decryptor only able to decrypt a single block of data that makes use of
 * a SecureRandom in the process (usually for algorithmic blinding).
 *
 * @param <T> the parameters type for the decryptor's cipher.
 */
public interface SingleBlockDecryptorUsingSecureRandom<T extends Parameters>
    extends SingleBlockDecryptor<T>, OperatorUsingSecureRandom<SingleBlockDecryptorUsingSecureRandom<T>>
{
    /**
     * Return a variant of this decryptor using the passed in random as its source of randomness.
     *
     * @param random the SecureRandom to use.
     * @return a new encryptor which will use random where random data is required.
     */
    SingleBlockDecryptorUsingSecureRandom<T> withSecureRandom(SecureRandom random);
}
