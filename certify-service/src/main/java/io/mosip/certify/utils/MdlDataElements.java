package io.mosip.certify.utils;

import java.util.List;

/**
 * What ISO/IEC 18013-5 Table 5 says about the data elements of an mDL, in the one place the
 * processor and the credential configuration validator both read it from.
 */
public final class MdlDataElements {

    /** The mDL document type (ISO/IEC 18013-5, 7.1). */
    public static final String DOC_TYPE = "org.iso.18013.5.1.mDL";

    /** The namespace of the Table 5 data elements. */
    public static final String NAMESPACE = "org.iso.18013.5.1";

    public static final String DRIVING_PRIVILEGES = "driving_privileges";

    public static final String ISSUE_DATE = "issue_date";

    public static final String EXPIRY_DATE = "expiry_date";

    /** Elements every mDL must carry (Table 5, presence "M"). */
    public static final List<String> MANDATORY = List.of(
            "family_name", "given_name", "birth_date", ISSUE_DATE, EXPIRY_DATE,
            "issuing_country", "issuing_authority", "document_number", "portrait",
            DRIVING_PRIVILEGES, "un_distinguishing_sign");

    private MdlDataElements() {
    }
}
