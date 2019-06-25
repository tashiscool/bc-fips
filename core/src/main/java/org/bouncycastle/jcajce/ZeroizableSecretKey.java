package org.bouncycastle.jcajce;

import javax.crypto.SecretKey;

/**
 * Interface for SecretKey's that can be explictly zeroized.
 * <p>
 * As this makes the key mutable, at the moment it only applies to MAC keys associated with key agreement schemes.
 * </p>
 */
public interface ZeroizableSecretKey
    extends SecretKey
{
    /**
     * Proactively zero out the key bytes.
     */
    void zeroize();
}
