package org.bouncycastle.crypto.fips;

import org.bouncycastle.crypto.internal.EngineProvider;

/**
 * The FipsBlockCipherProvider class is used to provide FIPS implementations to the general package so that the base FIPS engine can be
 * used in other ways than FIPS allows for.
 * <p>
 * This class is meant for internal use in the API only.
 * </p>
 */
public abstract class FipsEngineProvider<T>
    implements EngineProvider<T>
{
    //
    FipsEngineProvider()
    {

    }
}
