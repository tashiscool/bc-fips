/***************************************************************
 * DO NOT EDIT THIS CLASS bc-java SOURCE FILE

/******    DO NOT EDIT THIS CLASS bc-java SOURCE FILE     ******/
/***************************************************************/
package org.bouncycastle.crypto.internal.params;

import org.bouncycastle.crypto.internal.CipherParameters;

public class AEADParameters
    implements CipherParameters
{
    private final byte[] associatedText;
    private final byte[] nonce;
    private final KeyParameter key;
    private final int macSize;

    /**
     * Base constructor.
     *
     * @param key key to be used by underlying cipher
     * @param macSize macSize in bits
     * @param nonce nonce to be used
     */
    public AEADParameters(KeyParameter key, int macSize, byte[] nonce)
    {
        this(key, macSize, nonce, null);
    }

    /**
     * Base constructor.
     *
     * @param key key to be used by underlying cipher
     * @param macSize macSize in bits
     * @param nonce nonce to be used
     * @param associatedText initial associated text, if any
     */
    public AEADParameters(KeyParameter key, int macSize, byte[] nonce, byte[] associatedText)
    {
        this.key = key;
        this.nonce = nonce;
        this.macSize = macSize;
        this.associatedText = associatedText;
    }

    public KeyParameter getKey()
    {
        return key;
    }

    public int getMacSize()
    {
        return macSize;
    }

    public byte[] getAssociatedText()
    {
        return associatedText;
    }

    public byte[] getNonce()
    {
        return nonce;
    }
}
