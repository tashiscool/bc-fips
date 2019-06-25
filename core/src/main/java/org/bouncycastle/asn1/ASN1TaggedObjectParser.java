/***************************************************************/
/******    DO NOT EDIT THIS CLASS bc-java SOURCE FILE     ******/
/***************************************************************/
package org.bouncycastle.asn1;

import java.io.IOException;

/**
 * Parser interface for general tagged objects.
 */
public interface ASN1TaggedObjectParser
    extends ASN1Encodable, InMemoryRepresentable
{
    /**
     * Return the tag found at the start of this tagged object.
     *
     * @return tag No.
     */
    int getTagNo();

    /**
     * Return an object parser for the object found in this object.
     *
     * @param tag the actual tag number of the object (needed if implicit).
     * @param isExplicit true if the contained object was explicitly tagged, false if implicit.
     * @return a parser for the contained object,
     * @throws IOException in case of exception building the parser.
     */
    ASN1Encodable getObjectParser(int tag, boolean isExplicit)
        throws IOException;
}
