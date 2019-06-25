package org.bouncycastle.crypto.general;

import java.security.AccessController;
import java.security.PrivilegedAction;

import org.bouncycastle.crypto.SymmetricKey;
import org.bouncycastle.crypto.internal.ValidatedSymmetricKey;

class PrivilegedUtils
{
    static byte[] getKeyBytes(final SymmetricKey sKey)
    {
        return AccessController.doPrivileged(new PrivilegedAction<byte[]>()
        {
            public byte[] run()
            {
                return sKey.getKeyBytes();
            }
        });
    }

    static ValidatedSymmetricKey getValidatedKey(SymmetricKey key)
    {
        return new ValidatedSymmetricKey(key.getAlgorithm(), PrivilegedUtils.getKeyBytes(key));
    }
}
