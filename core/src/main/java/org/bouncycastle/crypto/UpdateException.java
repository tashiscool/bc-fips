package org.bouncycastle.crypto;

/**
 * A runtime exception that may be thrown by an update operation on an
 * UpdateOutputStream if the underlying stream throws an IOException.
 */
public class UpdateException
    extends RuntimeStreamException
{
    /**
     * Base constructor.
     *
     * @param msg a message concerning the exception.
     */
    public UpdateException(String msg)
    {
        super(msg);
    }

    /**
     * Constructor when this exception is due to another one.
     *
     * @param msg a message concerning the exception.
     * @param cause the exception that caused this exception to be thrown.
     */
    public UpdateException(String msg, Throwable cause)
    {
        super(msg, cause);
    }
}
