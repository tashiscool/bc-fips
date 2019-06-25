package org.bouncycastle.crypto.general;

/**
 * Base error class for errors that occur in the general classes.
 */
public class OperationError
    extends AssertionError
{
    private final Throwable cause;

    /**
     * Base constructor.
     *
     * @param message a message describing the error.
     */
    public OperationError(String message)
    {
        this(message, null);
    }

    /**
     * Constructor for an error associated with a specific algorithm.
     *
     * @param message a message describing the error.
     * @param cause the throwable that caused this exception to be raised.
     */
    public OperationError(String message, Throwable cause)
    {
        super(message);

        this.cause = cause;
    }

    public Throwable getCause()
    {
        return this.cause;
    }
}
