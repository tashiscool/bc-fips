package org.bouncycastle.crypto.general;

import org.bouncycastle.crypto.internal.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.internal.params.EcPrivateKeyParameters;
import org.bouncycastle.crypto.internal.params.EcPublicKeyParameters;

class DSTU4145KeyPairGenerator
    extends EcKeyPairGenerator
{
    public AsymmetricCipherKeyPair generateKeyPair()
    {
        AsymmetricCipherKeyPair pair = super.generateKeyPair();

        EcPublicKeyParameters pub = (EcPublicKeyParameters)pair.getPublic();
        EcPrivateKeyParameters priv = (EcPrivateKeyParameters)pair.getPrivate();

        pub = new EcPublicKeyParameters(pub.getQ().negate(), pub.getParameters());

        return new AsymmetricCipherKeyPair(pub, priv);
    }
}
