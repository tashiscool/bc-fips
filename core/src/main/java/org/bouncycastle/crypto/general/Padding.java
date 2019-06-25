package org.bouncycastle.crypto.general;

import org.bouncycastle.crypto.internal.BlockCipherPadding;

enum Padding
{
    PKCS7(BlockCipherPadding.PKCS7),
    ISO10126_2(BlockCipherPadding.ISO10126_2),
    X923(BlockCipherPadding.X923),
    ISO7816_4(BlockCipherPadding.ISO7816_4),
    TBC(BlockCipherPadding.TBC),
    CS1(BlockCipherPadding.CS1),
    CS2(BlockCipherPadding.CS2),
    CS3(BlockCipherPadding.CS3);

    private final BlockCipherPadding basePadding;

    Padding(BlockCipherPadding basePadding)
    {
        this.basePadding = basePadding;
    }

    BlockCipherPadding getBasePadding()
    {
        return basePadding;
    }
}
