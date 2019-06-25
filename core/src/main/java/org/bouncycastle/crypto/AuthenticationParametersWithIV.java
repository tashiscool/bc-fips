package org.bouncycastle.crypto;

import java.security.SecureRandom;

/**
 * Interface describing parameters used in an authentication mode, such as for a MAC, AEAD cipher, or
 * a HMAC.
 *
 * @param <T> the implementing type for this interface.
 */
public interface AuthenticationParametersWithIV<T extends AuthenticationParametersWithIV>
    extends AuthenticationParameters<T>, ParametersWithIV<T>
{
    /**
     * Return an implementation of our parameterized type with an IV constructed from the passed in SecureRandom.
     *
     * @param random source of randomness for iv (nonce)
     * @param ivLen length of the iv (nonce) in bytes to use with the algorithm.
     */
    T withIV(SecureRandom random, int ivLen);
}
