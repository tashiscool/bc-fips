package org.bouncycastle.crypto;

/**
 * Base interface for Public/Private keys.
 */
public interface AsymmetricKey
    extends Key
{
    /**
     * Return an ASN.1 encoding of the key wrapped in a PrivateKeyInfo or a SubjectPublicKeyInfo structure.
     *
     * @return an encoding of a PrivateKeyInfo or a SubjectPublicKeyInfo structure.
     */
    byte[] getEncoded();
}
