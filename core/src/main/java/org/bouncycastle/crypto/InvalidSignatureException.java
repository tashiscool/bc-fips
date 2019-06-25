package org.bouncycastle.crypto;

/**
 * Exception thrown when something unexpected is encountered in verifying a signature.
 */
public class InvalidSignatureException
    extends StreamException
{
    /**
     * Base constructor.
     *
     * @param msg a message concerning the exception.
     */
    public InvalidSignatureException(String msg)
    {
        super(msg);
    }

    /**
     * Constructor when this exception is due to another one.
     *
     * @param msg a message concerning the exception.
     * @param cause the exception that caused this exception to be thrown.
     */
    public InvalidSignatureException(String msg, Throwable cause)
    {
        super(msg, cause);
    }
}
