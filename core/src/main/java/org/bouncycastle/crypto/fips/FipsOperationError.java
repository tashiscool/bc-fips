package org.bouncycastle.crypto.fips;

/**
 * Base error class for FIPS errors.
 */
public class FipsOperationError
    extends AssertionError
{
    private final Throwable cause;

    /**
     * Base constructor.
     *
     * @param message a message describing the error.
     */
    public FipsOperationError(String message)
    {
        this(message, null);
    }

    /**
     * Constructor for an error associated with a specific algorithm.
     *
     * @param message a message describing the error.
     * @param cause the throwable that caused this exception to be raised.
     */
    public FipsOperationError(String message, Throwable cause)
    {
        super(message);

        this.cause = cause;
    }

    public Throwable getCause()
    {
        return this.cause;
    }
}
