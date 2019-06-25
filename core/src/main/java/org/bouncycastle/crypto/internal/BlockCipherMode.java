package org.bouncycastle.crypto.internal;

import java.security.SecureRandom;

import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.CryptoServicesRegistrar;

public enum BlockCipherMode
{
    ECB("ECB", false),
    CBC("CBC", true),
    CBCMAC("CBCMAC", false),
    CFB8("CFB8", true),
    CFB16("CFB16", true),
    CFB32("CFB32", true),
    CFB64("CFB64", true),
    CFB128("CFB128", true),
    CFB256("CFB256", true),
    OFB8("OFB8", true),
    OFB16("OFB16", true),
    OFB32("OFB32", true),
    OFB64("OFB64", true),
    OFB128("OFB128", true),
    OFB256("OFB256", true),
    CTR("CTR", true),
    GCM("GCM", true),
    CCM("CCM", true),
    OCB("OCB", true),
    EAX("EAX", true),
    GOSTMAC("MAC", false),
    CMAC("CMAC", false),
    GMAC("GMAC", true),
    WRAP("WRAP", false),
    WRAPPAD("WRAPPAD", false),
    RFC3217_WRAP("RFC3217WRAP", false),
    RFC3211_WRAP("RFC3211WRAP", true),
    OpenPGPCFB("OPENPGPCFB", false),     // IV is prepended
    GCFB("GCFB", true),
    GOFB("GOFB", true),
    CFB8MAC("CFB8MAC", false),
    ISO9797alg3("ISO979ALG3", false);

    private final String code;
    private final boolean expectsIV;

    BlockCipherMode(String code, boolean expectsIV)
    {
        this.code = code;
        this.expectsIV = expectsIV;
    }

    public String getCode()
    {
        return code;
    }

    public static BlockCipherMode getMode(Algorithm algorithm)
    {
        return null;
    }

    public boolean expectsIV()
    {
        return expectsIV;
    }

    public byte[] createDefaultIV(int blockSize, SecureRandom random)
    {
        byte[] iv;

        switch (this)
        {
        case CCM:
            iv = new byte[blockSize - 4];
            break;
        case OCB:
            iv = new byte[blockSize - 1];
            break;
        default:
            iv = new byte[blockSize];
        }

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
}
