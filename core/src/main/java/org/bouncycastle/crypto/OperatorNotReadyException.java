package org.bouncycastle.crypto;

/**
 * Exception thrown if an operator has not been properly initialized.
 */
public class OperatorNotReadyException
    extends RuntimeStreamException
{
    /**
     * Base constructor.
     *
     * @param msg a message concerning the exception.
     */
    public OperatorNotReadyException(String msg)
    {
        super(msg);
    }
}
