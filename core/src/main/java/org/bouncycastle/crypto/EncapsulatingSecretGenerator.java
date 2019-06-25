package org.bouncycastle.crypto;

import java.security.SecureRandom;

/**
 * Interface describing an encapsulated secret generator, such as for RSA KTS.
 *
 * @param <T> the type for the parameters used by this generator.
 */
public interface EncapsulatingSecretGenerator<T extends Parameters>
    extends OperatorUsingSecureRandom<EncapsulatingSecretGenerator<T>>
{
    /**
     * Return the parameters being used by this extractor.
     *
     * @return the extractor parameters.
     */
    T getParameters();

    /**
     * Generate an encapsulated secret, returning the encapsulation of the key material,
     * and the key material, or secret, as well.
     *
     * @return details for a new encapsulated secret.
     * @throws PlainInputProcessingException if an exception occurs on encapsulation.
     */
    SecretWithEncapsulation generate() throws PlainInputProcessingException;

    /**
     * Return a new generator which will use the passed in SecureRandom for generating the
     * key material, or secret, to be encapsulated.
     *
     * @param random the SecureRandom to use.
     * @return a generator using the passed in random as its source of key material.
     */
    EncapsulatingSecretGenerator<T> withSecureRandom(SecureRandom random);
}
