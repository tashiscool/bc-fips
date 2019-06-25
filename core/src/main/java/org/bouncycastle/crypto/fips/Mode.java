package org.bouncycastle.crypto.fips;

import java.security.SecureRandom;

import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.internal.BlockCipherMode;

enum Mode
{
    ECB(BlockCipherMode.ECB),
    CBC(BlockCipherMode.CBC),
    CFB8(BlockCipherMode.CFB8),
    CFB16(BlockCipherMode.CFB16),
    CFB32(BlockCipherMode.CFB32),
    CFB64(BlockCipherMode.CFB64),
    CFB128(BlockCipherMode.CFB128),
    OFB8(BlockCipherMode.OFB8),
    OFB16(BlockCipherMode.OFB16),
    OFB32(BlockCipherMode.OFB32),
    OFB64(BlockCipherMode.OFB64),
    OFB128(BlockCipherMode.OFB128),
    CTR(BlockCipherMode.CTR),
    GCM(BlockCipherMode.GCM),
    CCM(BlockCipherMode.CCM),
    OCB(BlockCipherMode.OCB),
    EAX(BlockCipherMode.EAX),
    CMAC(BlockCipherMode.CMAC),
    GMAC(BlockCipherMode.GMAC),
    WRAP(BlockCipherMode.WRAP),
    WRAPPAD(BlockCipherMode.WRAPPAD);

    private final BlockCipherMode baseMode;

    Mode(BlockCipherMode baseMode)
    {
        this.baseMode = baseMode;
    }

    BlockCipherMode getBaseMode()
    {
        return baseMode;
    }

    int checkIv(byte[] iv, int blockSize)
    {
        switch (baseMode)
        {
        case CBC:
        case CFB128:
        case CFB8:
        case CFB16:
        case CFB32:
        case CFB64:
        case OFB128:
        case OFB8:
        case OFB16:
        case OFB32:
        case OFB64:
            if (iv != null && iv.length != blockSize)
            {
                throw new IllegalArgumentException("IV must be " + blockSize + " bytes long");
            }
            break;
        case CTR:
            if (iv != null && iv.length > blockSize)
            {
                throw new IllegalArgumentException("CTR IV must be less than " + blockSize + " bytes long");
            }
        }

        return blockSize;
    }

    byte[] createDefaultIvIfNecessary(int blockSize, SecureRandom random)
    {
        if (baseMode.expectsIV())
        {
            return baseMode.createDefaultIV(blockSize, random);
        }

        return null;
    }

    byte[] createIvIfNecessary(int ivLen, SecureRandom random)
    {
        if (baseMode.expectsIV())
        {
            byte[] iv = new byte[ivLen];

            if (random != null)
            {
                random.nextBytes(iv);
            }
            else
            {
                CryptoServicesRegistrar.getSecureRandom().nextBytes(iv);
            }

            return iv;
        }

        return null;
    }
}
