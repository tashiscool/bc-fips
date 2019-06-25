package org.bouncycastle.crypto;

/**
 * Base interface for an output producing AEAD Encryptor supporting associated text.
 *
 * @param <T> the parameters type for the encryptor.
 */
public interface OutputAEADEncryptor<T extends Parameters>
    extends OutputEncryptor<T>, AADProcessor
{

}
