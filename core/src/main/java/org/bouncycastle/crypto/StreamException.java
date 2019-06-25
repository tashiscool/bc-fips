package org.bouncycastle.crypto;

import java.io.IOException;

/**
 * Parent class for exceptions arising due to cryptographic operations in the various streams created by the FIPS factory classes.
 */
public class StreamException
    extends IOException
{
    private final Throwable cause;

    /**
     * Base constructor.
     *
     * @param msg a message concerning the exception.
     */
    public StreamException(String msg)
    {
        this(msg, null);
    }

    /**
     * Constructor when this exception is due to another one.
     *
     * @param msg a message concerning the exception.
     * @param cause the exception that caused this exception to be thrown.
     */
    public StreamException(String msg, Throwable cause)
    {
        super(msg);
        this.cause = cause;
    }

    public Throwable getCause()
    {
        return cause;
    }
}
