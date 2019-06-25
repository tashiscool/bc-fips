package org.bouncycastle.crypto.internal.params;

public class DesEdeParameters
{
    /*
     * DES-EDE Key length in bytes.
     */
    static public final int DES_EDE_KEY_LENGTH = 24;

    /**
     * return true if the passed in key is a DES-EDE weak key.
     *
     * @param key bytes making up the key
     * @param offset offset into the byte array the key starts at
     * @param length number of bytes making up the key
     */
    public static boolean isWeakKey(
        byte[]  key,
        int     offset,
        int     length)
    {
        for (int i = offset; i < length; i += DesParameters.DES_KEY_LENGTH)
        {
            if (DesParameters.isWeakKey(key, i))
            {
                return true;
            }
        }

        return false;
    }

    public static boolean isRealEDEKey(byte[] key)
    {
        return key.length == 16 ? isReal2Key(key) : isReal3Key(key);
    }

    public static boolean isReal2Key(byte[] key)
    {
        boolean isValid = false;
        for (int i = 0; i != 8; i++)
        {
            if (key[i] != key[i + 8])
            {
                isValid = true;
            }
        }

        return isValid;
    }

    public static boolean isReal3Key(byte[] key)
    {
        boolean diff12 = false, diff13 = false, diff23 = false;

        for (int i = 0; i != 8; i++)
        {
            diff12 |= (key[i] != key[i + 8]);
            diff13 |= (key[i] != key[i + 16]);
            diff23 |= (key[i + 8] != key[i + 16]);
        }

        return diff12 && diff13 && diff23;
    }

    public static boolean isActuallyDesKey(byte[] key)
    {
        boolean isDesKey = true;

        if (key.length == 16)
        {
            for (int i = 0; i != 8; i++)
            {
                if (key[i] != key[i + 8])
                {
                    isDesKey = false;
                }
            }
        }
        else
        {
            for (int i = 0; i != 8; i++)
            {
                if (key[i] != key[i + 8] || key[i + 8] != key[i + 16])
                {
                    isDesKey = false;
                }
            }
        }

        return isDesKey;
    }
}
