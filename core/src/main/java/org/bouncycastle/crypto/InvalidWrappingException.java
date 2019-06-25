package org.bouncycastle.crypto;

/**
 * Exception thrown when an invalid key wrapping is encountered.
 */
public class InvalidWrappingException
    extends Exception
{
    /**
     * Base constructor.
     *
     * @param msg a message concerning the exception.
     */
    public InvalidWrappingException(String msg)
    {
        super(msg);
    }

    /**
     * Constructor when this exception is due to another one.
     *
     * @param msg a message concerning the exception.
     * @param cause the exception that caused this exception to be thrown.
     */
    public InvalidWrappingException(String msg, Throwable cause)
    {
        super(msg, cause);
    }
}
