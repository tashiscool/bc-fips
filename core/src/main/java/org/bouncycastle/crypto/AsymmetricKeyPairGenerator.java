package org.bouncycastle.crypto;

import org.bouncycastle.crypto.asymmetric.AsymmetricKeyPair;

/**
 * Interface describing a key generator for public/private key pairs.
 *
 * @param <T> the generator's parameters type.
 * @param <P> the type of the public key.
 * @param <S> the type of the private key.
 */
public interface AsymmetricKeyPairGenerator<T extends Parameters, P extends AsymmetricPublicKey, S extends AsymmetricPrivateKey>
{
    /**
     * Return the parameters being used by this generator.
     *
     * @return the generator's parameters.
     */
    T getParameters();

    /**
     * Return a newly generated key pair.
     *
     * @return a new key pair.
     */
    AsymmetricKeyPair<P, S> generateKeyPair();
}
