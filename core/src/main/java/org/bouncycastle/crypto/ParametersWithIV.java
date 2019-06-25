package org.bouncycastle.crypto;

import java.security.SecureRandom;

/**
 * Interface describing parameters that have an initialization vector (IV) associated with them.
 *
 * @param <T>
 */
public interface ParametersWithIV<T extends Parameters>
    extends Parameters
{
    /**
     * Return the initialization vector associated with this parameter set.
     *
     * @return the IV for these parameters.
     */
    byte[] getIV();

    /**
     * Create a new parameter set with a different IV.
     *
     * @param iv the IV to use.
     * @return a copy of the current parameter set with the new IV.
     */
    T withIV(byte[] iv);

    /**
     * Create a new parameter set with a different IV based on the output
     * of the passed in random.
     *
     * @param random the SecureRandom to use as the source of IV data.
     * @return a copy of the current parameter set with the new IV.
     */
    T withIV(SecureRandom random);
}
