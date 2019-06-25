package org.bouncycastle.jcajce;

import java.util.concurrent.atomic.AtomicBoolean;

import javax.crypto.SecretKey;

import org.bouncycastle.util.Arrays;

/**
 * Carrier class for an agreement secret key, as well as details about the MAC key if confirmation is provided.
 */
public final class AgreedKeyWithMacKey
    implements SecretKey
{
    private final SecretKey secretKey;
    private final byte[] macKey;
    private final String macAlgorithm;

    private final AtomicBoolean isZeroed = new AtomicBoolean(false);

    /**
     * Basic constructor, no MAC.
     *
     * @param secretKey the secret key that was arrived at.
     */
    public AgreedKeyWithMacKey(SecretKey secretKey)
    {
        this(secretKey, null, null);
    }

    /**
     * Constructor containing MAC details
     *
     * @param secretKey the secret key that was arrived at.
     * @param macAlgorithm the MAC algorithm to use.
     * @param macKey the bytes representing the agreed MAC key.
     */
    public AgreedKeyWithMacKey(SecretKey secretKey, String macAlgorithm, byte[] macKey)
    {
        this.secretKey = secretKey;
        this.macKey = Arrays.clone(macKey);
        this.macAlgorithm = macAlgorithm;
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

    public boolean equals(Object o)
    {
        return secretKey.equals(o);
    }

    public int hashCode()
    {
        return secretKey.hashCode();
    }

    private byte[] getMacKeyBytes()
    {
        if (isZeroed.get())
        {
            return null;
        }

        return macKey;
    }

    /**
     * Return a key for the MAC associated with the KTS process (if available).
     *
     * @return the MAC secret key (null otherwise).
     */
    public ZeroizableSecretKey getMacKey()
    {
        if (macKey == null)
        {
            return null;
        }

        return new ZeroizableSecretKey()
        {
            /**
             * Zero out the MAC key associated with this agreed key.
             */
            public void zeroize()
            {
                isZeroed.set(true);

                if (macKey != null)
                {
                    Arrays.fill(macKey, (byte)0);
                }
            }

            public String getAlgorithm()
            {
                return macAlgorithm;
            }

            public String getFormat()
            {
                return "RAW";
            }

            public byte[] getEncoded()
            {
                return getMacKeyBytes();
            }
        };
    }
}
