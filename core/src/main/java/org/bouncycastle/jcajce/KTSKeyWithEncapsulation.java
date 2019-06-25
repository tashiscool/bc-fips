package org.bouncycastle.jcajce;

import javax.crypto.SecretKey;

import org.bouncycastle.util.Arrays;

/**
 * Carrier class for a KTS secret key plus its encapsulation, as well as details about the MAC key if provided.
 */
public final class KTSKeyWithEncapsulation
    implements SecretKey
{
    private final SecretKey secretKey;
    private final byte[] encapsulation;

    /**
     * Basic constructor.
     *
     * @param secretKey the secret key that was arrived at.
     * @param encapsulation the encapsulation the key data was carried in.
     */
    public KTSKeyWithEncapsulation(SecretKey secretKey, byte[] encapsulation)
    {
        this.secretKey = secretKey;
        this.encapsulation = Arrays.clone(encapsulation);
    }

    /**
     * Return the algorithm for the agreed secret key.
     *
     * @return the secret key value.
     */
    public String getAlgorithm()
    {
        return secretKey.getAlgorithm();
    }

    /**
     * Return the format for the agreed secret key.
     *
     * @return the secret key format.
     */
    public String getFormat()
    {
        return secretKey.getFormat();
    }

    /**
     * Return the encoding of the agreed secret key.
     *
     * @return the secret key encoding.
     */
    public byte[] getEncoded()
    {
        return secretKey.getEncoded();
    }

    /**
     * Return the encapsulation that carried the key material used in creating the agreed secret key.
     *
     * @return the encrypted encapsulation of the agreed secret key.
     */
    public byte[] getEncapsulation()
    {
        return Arrays.clone(encapsulation);
    }

    /**
     * Return the mac key if there is one present.
     *
     * @return the associated MAC key for this KTS key (null if there isn't one).
     */
    public ZeroizableSecretKey getMacKey()
    {
        if (secretKey instanceof AgreedKeyWithMacKey)
        {
            return ((AgreedKeyWithMacKey)secretKey).getMacKey();
        }

        return null;
    }

    public boolean equals(Object o)
    {
        return secretKey.equals(o);
    }

    public int hashCode()
    {
        return secretKey.hashCode();
    }
}
