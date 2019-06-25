package org.bouncycastle.crypto.fips;

import org.bouncycastle.crypto.AsymmetricPrivateKey;
import org.bouncycastle.crypto.AsymmetricPublicKey;
import org.bouncycastle.crypto.Parameters;
import org.bouncycastle.crypto.SignatureOperatorFactory;

/**
 * Base class for the approved mode SignatureOperatorFactory implementations.
 *
 * @param <T> the parameters type associated with the final implementation of this factory.
 */
public abstract class FipsSignatureOperatorFactory<T extends Parameters>
    implements SignatureOperatorFactory<T>
{
    // package protect constructor
    FipsSignatureOperatorFactory()
    {
        FipsStatus.isReady();
    }

    public abstract FipsOutputSigner<T> createSigner(AsymmetricPrivateKey key, T parameters);

    public abstract FipsOutputVerifier<T> createVerifier(AsymmetricPublicKey key, T parameters);
}
