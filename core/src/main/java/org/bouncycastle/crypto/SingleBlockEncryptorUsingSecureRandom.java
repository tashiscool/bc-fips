package org.bouncycastle.crypto;

import java.security.SecureRandom;

/**
 * Interface for a encryptor only able to encrypt a single block of data that makes use of
 * a SecureRandom in the process.
 *
 * @param <T> the parameters type for the encryptor's cipher.
 */
public interface SingleBlockEncryptorUsingSecureRandom<T extends Parameters>
    extends SingleBlockEncryptor<T>, OperatorUsingSecureRandom<SingleBlockEncryptorUsingSecureRandom<T>>
{
    /**
     * Return a variant of this encryptor using the passed in random as its source of randomness.
     *
     * @param random the SecureRandom to use.
     * @return a new encryptor which will use random where random data is required.
     */
    SingleBlockEncryptorUsingSecureRandom<T> withSecureRandom(SecureRandom random);
}
