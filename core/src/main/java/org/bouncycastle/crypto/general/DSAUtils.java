package org.bouncycastle.crypto.general;

class DSAUtils
{
    static void reverseBytes(byte[] bytes)
    {
        byte tmp;
        for (int i = 0; i < bytes.length / 2; i++)
        {
            tmp = bytes[i];
            bytes[i] = bytes[bytes.length - 1 - i];
            bytes[bytes.length - 1 - i] = tmp;
        }
    }
}
