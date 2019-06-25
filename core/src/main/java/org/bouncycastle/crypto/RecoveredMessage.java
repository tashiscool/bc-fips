package org.bouncycastle.crypto;

/**
 * Interface describing recovered message details from a signature.
 */
public interface RecoveredMessage
{
    /**
     * Return the content of the recovered message in the signature.
     *
     * @return the recovered message.
     */
    byte[] getContent();

    /**
     * Return whether or not the full message was recovered.
     *
     * @return true if the full message was recovered, false otherwise.
     */
    boolean isFullMessage();
}
