package org.bouncycastle.crypto;

/**
 * Parent class for exceptions arising due to cryptographic operations in the various streams created by the FIPS factory classes.
 */
public class RuntimeStreamException
    extends RuntimeException
{
    /**
     * Base constructor.
     *
     * @param msg a message concerning the exception.
     */
    public RuntimeStreamException(String msg)
    {
        super(msg);
    }

    /**
     * Constructor when this exception is due to another one.
     *
     * @param msg a message concerning the exception.
     * @param cause the exception that caused this exception to be thrown.
     */
    public RuntimeStreamException(String msg, Throwable cause)
    {
        super(msg, cause);
    }
}
