package org.bouncycastle.crypto.fips;

import org.bouncycastle.crypto.Algorithm;

/**
 * Error thrown on an unapproved operation.
 */
public class FipsUnapprovedOperationError
    extends FipsOperationError
{
    /**
     * Base constructor.
     *
     * @param message a message describing the error.
     */
    public FipsUnapprovedOperationError(String message)
    {
        super(message);
    }

    /**
     * Constructor for an error associated with a specific algorithm.
     *
     * @param message a message describing the error.
     * @param algorithm the algorithm the failure was for.
     */
    public FipsUnapprovedOperationError(String message, Algorithm algorithm)
    {
        super(message + ": " + algorithm.getName());
    }
}
