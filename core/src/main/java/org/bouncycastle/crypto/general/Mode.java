package org.bouncycastle.crypto.general;

import java.security.SecureRandom;

import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.internal.BlockCipherMode;

enum Mode
{
    ECB(BlockCipherMode.ECB),
    CBC(BlockCipherMode.CBC),
    CBCMAC(BlockCipherMode.CBCMAC),
    CFB8(BlockCipherMode.CFB8),
    CFB8MAC(BlockCipherMode.CFB8MAC),
    CFB16(BlockCipherMode.CFB16),
    CFB32(BlockCipherMode.CFB32),
    CFB64(BlockCipherMode.CFB64),
    CFB128(BlockCipherMode.CFB128),
    CFB256(BlockCipherMode.CFB256),
    OFB8(BlockCipherMode.OFB8),
    OFB16(BlockCipherMode.OFB16),
    OFB32(BlockCipherMode.OFB32),
    OFB64(BlockCipherMode.OFB64),
    OFB128(BlockCipherMode.OFB128),
    OFB256(BlockCipherMode.OFB256),
    CTR(BlockCipherMode.CTR),
    GCM(BlockCipherMode.GCM),
    CCM(BlockCipherMode.CCM),
    OCB(BlockCipherMode.OCB),
    EAX(BlockCipherMode.EAX),
    GOSTMAC(BlockCipherMode.GOSTMAC),
    CMAC(BlockCipherMode.CMAC),
    GMAC(BlockCipherMode.GMAC),
    WRAP(BlockCipherMode.WRAP),
    WRAPPAD(BlockCipherMode.WRAPPAD),
    RFC3217_WRAP(BlockCipherMode.RFC3217_WRAP),
    RFC3211_WRAP(BlockCipherMode.RFC3211_WRAP),
    OpenPGPCFB(BlockCipherMode.OpenPGPCFB),
    GCFB(BlockCipherMode.GCFB),
    GOFB(BlockCipherMode.GOFB),
    ISO9797alg3(BlockCipherMode.ISO9797alg3);

    private final BlockCipherMode baseMode;

    Mode(BlockCipherMode baseMode)
    {
        this.baseMode = baseMode;
    }

    BlockCipherMode getBaseMode()
    {
        return baseMode;
    }

    byte[] checkIv(byte[] iv, int blockSize)
    {
        switch (baseMode)
        {
        case CBC:
        case CFB8:
        case CFB16:
        case CFB32:
        case CFB64:
        case CFB128:
        case CFB256:
        case OFB8:
        case OFB16:
        case OFB32:
        case OFB64:
        case OFB128:
        case OFB256:
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

        return iv;
    }

    byte[] createDefaultIvIfNecessary(int size, SecureRandom random)
    {
        if (baseMode.expectsIV())
        {
            return baseMode.createDefaultIV(size, random);
        }

        return null;
    }

    byte[] createIvIfNecessary(int blockSize, SecureRandom random)
    {
        if (baseMode.expectsIV())
        {
            byte[] iv = new byte[blockSize];

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
