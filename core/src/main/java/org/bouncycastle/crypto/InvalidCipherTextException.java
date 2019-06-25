package org.bouncycastle.crypto;

/**
 * Exception thrown when something unexpected is encountered processing an encrypted stream.
 */
public class InvalidCipherTextException
    extends StreamException
{
    /**
     * Base constructor.
     *
     * @param msg a message concerning the exception.
     */
    public InvalidCipherTextException(String msg)
    {
        super(msg);
    }

    /**
     * Constructor when this exception is due to another one.
     *
     * @param msg a message concerning the exception.
     * @param cause the exception that caused this exception to be thrown.
     */
    public InvalidCipherTextException(String msg, Throwable cause)
    {
        super(msg, cause);
    }
}
