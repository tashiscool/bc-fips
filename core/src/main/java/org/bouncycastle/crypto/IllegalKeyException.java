package org.bouncycastle.crypto;

/**
 * Exception thrown when an attempt is made to use an illegal key with an algorithm, A key
 * may be regarded as illegal if it has been created for a specific mode of a particular algorithm
 * and an attempt is made to use it for a different mode.
 */
public class IllegalKeyException
    extends IllegalArgumentException
{
    /**
     * Base constructor.
     *
     * @param message a message concerning the exception.
     */
    public IllegalKeyException(String message)
    {
        super(message);
    }
}
