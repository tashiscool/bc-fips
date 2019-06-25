package org.bouncycastle.crypto;

/**
 * Interface for an output signer that also supports message recovery from the signature.
 *
 * @param <T> the parameters type for the signer.
 */
public interface OutputSignerWithMessageRecovery<T extends Parameters>
    extends OutputSigner<T>
{
    /**
     * Return the recovered message details.
     *
     * @return recovered message details.
     */
    RecoveredMessage getRecoveredMessage();
}
