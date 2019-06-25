package org.bouncycastle.crypto;

/**
 * Base interface for an output producing AEAD Decryptor supporting associated text.
 *
 * @param <T> the parameters type for the decryptor.
 */
public interface OutputAEADDecryptor<T extends Parameters>
    extends OutputDecryptor<T>, AADProcessor
{

}
