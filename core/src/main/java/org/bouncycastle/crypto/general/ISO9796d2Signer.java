package org.bouncycastle.crypto.general;

import org.bouncycastle.crypto.fips.FipsRSA;
import org.bouncycastle.crypto.internal.AsymmetricBlockCipher;
import org.bouncycastle.crypto.internal.Digest;
import org.bouncycastle.crypto.internal.signers.BaseISO9796d2Signer;
import org.bouncycastle.crypto.internal.util.ISOTrailers;

class ISO9796d2Signer
    extends BaseISO9796d2Signer
{
    /**
     * Generate a signer for the with either implicit or explicit trailers
     * for ISO9796-2.
     *
     * @param digest digest to use.
     */
    public ISO9796d2Signer(
        Digest digest)
    {
        super((AsymmetricBlockCipher)FipsRegister.getProvider(FipsRSA.ALGORITHM).createEngine(), digest, ISOTrailers.noTrailerAvailable(digest));
    }
}
