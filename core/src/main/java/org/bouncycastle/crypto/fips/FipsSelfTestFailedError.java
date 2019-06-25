package org.bouncycastle.crypto.fips;

import org.bouncycastle.crypto.Algorithm;

/**
 * Error thrown if a self test fails.
 */
public class FipsSelfTestFailedError
    extends FipsOperationError
{
    /**
     * Base constructor.
     *
     * @param message a message describing the error.
     * @param algorithm the algorithm the failure was for.
     */
    public FipsSelfTestFailedError(String message, Algorithm algorithm)
    {
        super(message + ": " + algorithm.getName());
    }
}
