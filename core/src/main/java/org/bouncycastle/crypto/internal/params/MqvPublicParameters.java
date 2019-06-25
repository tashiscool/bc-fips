package org.bouncycastle.crypto.internal.params;

import org.bouncycastle.crypto.IllegalKeyException;
import org.bouncycastle.crypto.internal.CipherParameters;

public class MqvPublicParameters
    implements CipherParameters
{
    private DhPublicKeyParameters staticPublicKey;
    private DhPublicKeyParameters ephemeralPublicKey;

    public MqvPublicParameters(
        DhPublicKeyParameters staticPublicKey,
        DhPublicKeyParameters ephemeralPublicKey)
    {
        this.staticPublicKey = staticPublicKey;
        this.ephemeralPublicKey = ephemeralPublicKey;

        if (!staticPublicKey.getParameters().equals(ephemeralPublicKey.getParameters()))
        {
            throw new IllegalKeyException("Static and ephemeral keys have different domain parameters");
        }
    }

    public DhPublicKeyParameters getStaticPublicKey()
    {
        return staticPublicKey;
    }

    public DhPublicKeyParameters getEphemeralPublicKey()
    {
        return ephemeralPublicKey;
    }
}
