package org.bouncycastle.crypto.util;

import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

/**
 * Builder and holder class for preparing SP 800-56A/56B compliant MacData. Elements in the data are copied in
 * directly as byte arrays,
 */
public final class ByteMacData
{
    /**
     * Standard type strings for the headers of KAS/KTS MAC calculations.
     */
    public enum Type
    {
        UNILATERALU("KC_1_U"),
        UNILATERALV("KC_1_V"),
        BILATERALU("KC_2_U"),
        BILATERALV("KC_2_V");

        private final String enc;

        Type(String enc)
        {
            this.enc = enc;
        }

        public byte[] getHeader()
        {
            return Strings.toByteArray(enc);
        }
    }

    /**
     * Builder to create OtherInfo
     */
    public static final class Builder
    {
        private final Type type;

        private byte[] idU;
        private byte[] idV;
        private byte[] ephemDataU;
        private byte[] ephemDataV;
        private byte[] text;

        /**
         * Create a basic builder with just the compulsory fields.
         *
         * @param type the MAC header
         * @param idU  sender party ID.
         * @param idV  receiver party ID.
         * @param ephemDataU ephemeral data from sender.
         * @param ephemDataV ephemeral data from receiver.
         */
        public Builder(Type type, byte[] idU, byte[] idV, byte[] ephemDataU, byte[] ephemDataV)
        {
            this.type = type;
            this.idU = Arrays.clone(idU);
            this.idV = Arrays.clone(idV);
            this.ephemDataU = Arrays.clone(ephemDataU);
            this.ephemDataV = Arrays.clone(ephemDataV);
        }

        /**
         * Add optional text.
         *
         * @param text optional agreed text to add to the MAC.
         * @return the current builder instance.
         */
        public Builder withText(byte[] text)
        {
            this.text = DerUtil.toByteArray(new DERTaggedObject(false, 0, DerUtil.getOctetString(text)));

            return this;
        }

        public ByteMacData build()
        {
            switch (type)
            {
            case UNILATERALU:
            case BILATERALU:
                return new ByteMacData(concatenate(type.getHeader(), idU, idV, ephemDataU, ephemDataV, text));
            case UNILATERALV:
            case BILATERALV:
                return new ByteMacData(concatenate(type.getHeader(), idV, idU, ephemDataV, ephemDataU, text));
            }

            throw new IllegalStateException("Unknown type encountered in build");   // should never happen
        }

        private byte[] concatenate(byte[] header, byte[] id1, byte[] id2, byte[] ed1, byte[] ed2, byte[] text)
        {
            return Arrays.concatenate(Arrays.concatenate(header, id1, id2), Arrays.concatenate(ed1, ed2, text));
        }
    }

    private final byte[] macData;

    private ByteMacData(byte[] macData)
    {
        this.macData = macData;
    }

    public byte[] getMacData()
    {
        return Arrays.clone(macData);
    }
}
