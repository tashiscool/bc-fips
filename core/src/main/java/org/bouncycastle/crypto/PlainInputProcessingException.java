package org.bouncycastle.crypto;

/**
 * Exception thrown when something unexpected is encountered processing plain text input data for signature or block encryption.
 */
public class PlainInputProcessingException
    extends StreamException
{
    /**
     * Base constructor.
     *
     * @param msg a message concerning the exception.
     */
    public PlainInputProcessingException(String msg)
    {
        super(msg);
    }

    /**
     * Constructor when this exception is due to another one.
     *
     * @param msg a message concerning the exception.
     * @param cause the exception that caused this exception to be thrown.
     */
    public PlainInputProcessingException(String msg, Throwable cause)
    {
        super(msg, cause);
    }
}
