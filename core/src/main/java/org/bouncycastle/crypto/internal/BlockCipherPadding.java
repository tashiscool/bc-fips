package org.bouncycastle.crypto.internal;

public enum BlockCipherPadding
{
    PKCS7("PKCS7", false),
    ISO10126_2("ISO10126-2", true),
    X923("X9.23", true),
    ISO7816_4("ISO7816-4", false),
    TBC("TBC", false),
    CS1("CS1", false),
    CS2("CS2", false),
    CS3("CS3", false);

    private final String code;
    private final boolean requiresRandom;

    BlockCipherPadding(String code, boolean requiresRandom)
    {
        this.code = code;
        this.requiresRandom = requiresRandom;
    }

    public String getCode()
    {
        return code;
    }

    public boolean requiresRandom()
    {
        return requiresRandom;
    }
}
