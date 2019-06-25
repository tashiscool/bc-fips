package org.bouncycastle.crypto;

/**
 * Interface describing a symmetric key.
 */
public interface SymmetricKey
    extends Key
{
    /**
     * Return the bytes associated with this key.
     *
     * @return key bytes, null or exception if they are not available.
     */
    byte[] getKeyBytes();
}
