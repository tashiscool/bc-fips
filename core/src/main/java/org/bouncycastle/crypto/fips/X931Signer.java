package org.bouncycastle.crypto.fips;

import org.bouncycastle.crypto.internal.AsymmetricBlockCipher;
import org.bouncycastle.crypto.internal.Digest;
import org.bouncycastle.crypto.internal.signers.BaseX931Signer;
import org.bouncycastle.crypto.internal.util.ISOTrailers;

/**
 * X9.31-1998 - signing using a hash.
 * <p>
 * The message digest hash, H, is encapsulated to form a byte string as follows
 * <pre>
 * EB = 06 || PS || 0xBA || H || TRAILER
 * </pre>
 * where PS is a string of bytes all of value 0xBB of length such that |EB|=|n|, and TRAILER is the ISO/IEC 10118 part number† for the digest. The byte string, EB, is converted to an integer value, the message representative, f.
 */
class X931Signer
    extends BaseX931Signer
{
    /**
     * Generate a signer for the with either implicit or explicit trailers
     * for ISO9796-2.
     *
     * @param cipher base cipher to use for signature creation/verification
     * @param digest digest to use.
     * @param implicit whether or not the trailer is implicit or gives the hash.
     */
    public X931Signer(
        AsymmetricBlockCipher cipher,
        Digest digest,
        boolean implicit)
    {
        super(cipher, digest, implicit);
    }

    /**
     * Constructor for a signer with an explicit digest trailer.
     *
     * @param cipher cipher to use.
     * @param digest digest to sign with.
     */
    public X931Signer(
        AsymmetricBlockCipher cipher,
        Digest digest)
    {
        this(cipher, digest, ISOTrailers.noTrailerAvailable(digest));
    }

}
