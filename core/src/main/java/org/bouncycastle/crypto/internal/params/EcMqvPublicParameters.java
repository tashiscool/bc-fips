package org.bouncycastle.crypto.internal.params;

import org.bouncycastle.crypto.IllegalKeyException;
import org.bouncycastle.crypto.internal.CipherParameters;

public class EcMqvPublicParameters
    implements CipherParameters
{
    private EcPublicKeyParameters staticPublicKey;
    private EcPublicKeyParameters ephemeralPublicKey;

    public EcMqvPublicParameters(
        EcPublicKeyParameters staticPublicKey,
        EcPublicKeyParameters ephemeralPublicKey)
    {
        this.staticPublicKey = staticPublicKey;
        this.ephemeralPublicKey = ephemeralPublicKey;

        if (!staticPublicKey.getParameters().equals(ephemeralPublicKey.getParameters()))
        {
            throw new IllegalKeyException("Static and ephemeral keys have different domain parameters");
        }
    }

    public EcPublicKeyParameters getStaticPublicKey()
    {
        return staticPublicKey;
    }

    public EcPublicKeyParameters getEphemeralPublicKey()
    {
        return ephemeralPublicKey;
    }
}
