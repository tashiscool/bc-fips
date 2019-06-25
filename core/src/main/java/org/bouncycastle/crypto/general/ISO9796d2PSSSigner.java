package org.bouncycastle.crypto.general;

import org.bouncycastle.crypto.fips.FipsRSA;
import org.bouncycastle.crypto.internal.AsymmetricBlockCipher;
import org.bouncycastle.crypto.internal.Digest;
import org.bouncycastle.crypto.internal.signers.BaseISO9796d2PSSSigner;
import org.bouncycastle.crypto.internal.util.ISOTrailers;

class ISO9796d2PSSSigner
    extends BaseISO9796d2PSSSigner
{
    /**
     * Generate a signer for the with either implicit or explicit trailers
     * for ISO9796-2.
     *
     * @param digest digest to use.
     */
    public ISO9796d2PSSSigner(
        Digest digest,
        int    saltLength)
    {
        super((AsymmetricBlockCipher)FipsRegister.getProvider(FipsRSA.ALGORITHM).createEngine(), digest, saltLength, ISOTrailers.noTrailerAvailable(digest));
    }

    /**
     * Generate a signer for the with either implicit or explicit trailers
     * for ISO9796-2.
     *
     * @param digest digest to use.
     */
    public ISO9796d2PSSSigner(
        Digest digest,
        byte[] salt)
    {
        super((AsymmetricBlockCipher)FipsRegister.getProvider(FipsRSA.ALGORITHM).createEngine(), digest, salt, ISOTrailers.noTrailerAvailable(digest));
    }
}
