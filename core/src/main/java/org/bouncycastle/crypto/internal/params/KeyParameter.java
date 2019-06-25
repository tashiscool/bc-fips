package org.bouncycastle.crypto.internal.params;

import org.bouncycastle.crypto.internal.CipherParameters;

/**
 * Created by dgh on 16/06/15.
 */
public interface KeyParameter
    extends CipherParameters
{
    byte[] getKey();
}
