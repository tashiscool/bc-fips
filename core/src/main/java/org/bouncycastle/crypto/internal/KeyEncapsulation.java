/***************************************************************/
/******    DO NOT EDIT THIS CLASS bc-java SOURCE FILE     ******/
/***************************************************************/
package org.bouncycastle.crypto.internal;

/**
 * The basic interface for key encapsulation mechanisms.
 */
public interface KeyEncapsulation
{
    /**
     * Initialise the key encapsulation mechanism.
     */
    public void init(CipherParameters param);

    /**
     * Encapsulate a randomly generated session key.    
     */
    public CipherParameters encrypt(byte[] out, int outOff, int keyLen);
    
    /**
     * Decapsulate an encapsulated session key.
     */
    public CipherParameters decrypt(byte[] in, int inOff, int inLen, int keyLen);
}
