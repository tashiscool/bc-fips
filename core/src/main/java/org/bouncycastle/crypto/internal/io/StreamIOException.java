package org.bouncycastle.crypto.internal.io;

import java.io.IOException;

/**
 * For JDK 1.5 compatibility
 */
class StreamIOException
    extends IOException
{
    private final Throwable cause;

    StreamIOException(String message, Throwable cause)
    {
        super(message);
        this.cause = cause;
    }

    public Throwable getCause()
    {
        return cause;
    }
}
