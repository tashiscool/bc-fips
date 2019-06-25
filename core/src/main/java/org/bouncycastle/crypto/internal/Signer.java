package org.bouncycastle.crypto.internal;

import org.bouncycastle.crypto.InvalidSignatureException;

/**
 * Generic signer interface for hash based and message recovery signers.
 */
public interface Signer 
{
    /**
     * Initialise the signer for signing or verification.
     * 
     * @param forSigning true if for signing, false otherwise
     * @param param necessary parameters.
     */
    void init(boolean forSigning, CipherParameters param);

    /**
     * update the internal digest with the byte b
     */
    void update(byte b);

    /**
     * update the internal digest with the byte array in
     */
    void update(byte[] in, int off, int len);

    /**
     * generate a signature for the message we've been loaded with using
     * the key we were initialised with.
     */
    byte[] generateSignature()
        throws CryptoException, DataLengthException;

    /**
     * return true if the internal state represents the signature described
     * in the passed in array.
     */
    boolean verifySignature(byte[] signature)
        throws InvalidSignatureException;
    
    /**
     * reset the internal state
     */
    void reset();
}
