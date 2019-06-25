package org.bouncycastle.crypto;

/**
 * Base interface for a password based deriver of bytes for symmetric keys.
 *
 * @param <T> the parameters type for the deriver.
 */
public interface PasswordBasedDeriver<T>
{
    /**
     * The target key type we are trying to produce a key for.
     */
    static enum KeyType
    {
        /**
         * Target key for a symmetric cipher.
         */
        CIPHER,
        /**
         * Target key for a MAC.
         */
        MAC,
    }

    /**
     * Return the parameters for this deriver.
     *
     * @return the deriver's parameters.
     */
    T getParameters();

    /**
     * Derive a key of the given keySizeInBytes length.
     *
     * @param keyType type of key to be calculated.
     * @param keySizeInBytes the number of bytes to be produced.
     * @return a byte array containing the raw key data.
     */
    byte[] deriveKey(KeyType keyType, int keySizeInBytes);

    /**
     * Derive a key of the given keySizeInBytes length and an iv of ivSizeInBytes length.
     *
     * @param keyType type of key to be calculated.
     * @param keySizeInBytes the number of bytes to be produced.
     * @param ivSizeInBytes the number of bytes to be produced.
     * @return a 2 element byte[] array containing the raw key data in element 0, the iv in element 1.
     */
    byte[][] deriveKeyAndIV(KeyType keyType, int keySizeInBytes, int ivSizeInBytes);
}
