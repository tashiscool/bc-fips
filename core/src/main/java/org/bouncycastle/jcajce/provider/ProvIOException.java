package org.bouncycastle.jcajce.provider;

import java.io.IOException;

/**
 * For JDK 1.5 compatibility
 */
class ProvIOException
    extends IOException
{
    private final Throwable cause;

    ProvIOException(String message, Throwable cause)
    {
        super(message);
        this.cause = cause;
    }

    public Throwable getCause()
    {
        return cause;
    }
}
