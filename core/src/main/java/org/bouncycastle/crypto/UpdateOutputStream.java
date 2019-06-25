package org.bouncycastle.crypto;

import java.io.IOException;
import java.io.OutputStream;

/**
 * An extension of output stream that provides update methods which allow
 * for data to feed into the stream without the need to handle checked exceptions.
 */
public abstract class UpdateOutputStream
    extends OutputStream
{
    /**
     * Update the stream with the passed in byte.
     *
     * @param b the data to be written to the stream.
     */
    public final void update(byte b)
    {
        try
        {
            write(b);
        }
        catch (IOException e)
        {
            if (e.getCause() != null)
            {
                throw new UpdateException(e.getClass().getName() + ": " + e.getMessage(), e.getCause());
            }
            else
            {
                throw new UpdateException("Exception processing data: " + e.getMessage(), e);
            }
        }
    }

    /**
     * Update the stream with the passed in buffer.
     *
     * @param buffer the data to be written to the stream.
     */
    public final void update(byte[] buffer)
    {
        update(buffer, 0, buffer.length);
    }

    /**
     * Update the stream with a section of the passed in buffer.
     *
     * @param buffer the buffer holding the data to be written.
     * @param off the offset into buffer at which the data starts.
     * @param len the length of the data to be written.
     */
    public final void update(byte[] buffer, int off, int len)
    {
        try
        {
            write(buffer, off, len);
        }
        catch (IOException e)
        {
            if (e.getCause() != null)
            {
                throw new UpdateException(e.getClass().getName() + ": " + e.getMessage(), e.getCause());
            }
            else
            {
                throw new UpdateException("Exception processing data: " + e.getMessage(), e);
            }
        }
    }
}
