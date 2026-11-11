package io.mosip.certify.utils;

import java.util.Collection;
import java.util.List;
import java.util.Set;

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

    /** Elements whose date-only value is a full-date (CBOR tag 1004). */
    public static final Set<String> FULL_DATE = Set.of("birth_date", ISSUE_DATE, EXPIRY_DATE);

    /** Elements that may also be a date-time instead, a tdate (CBOR tag 0). */
    public static final Set<String> FULL_DATE_OR_TDATE = Set.of(ISSUE_DATE, EXPIRY_DATE);

    /** The dates inside each driving_privileges entry, also full-dates (7.2.4). */
    public static final Set<String> DRIVING_PRIVILEGE_FULL_DATE = Set.of(ISSUE_DATE, EXPIRY_DATE);

    /** The keys a DrivingPrivilege may have (7.2.4); vehicle_category_code is required. */
    public static final Set<String> DRIVING_PRIVILEGE_KEYS = Set.of("vehicle_category_code", ISSUE_DATE, EXPIRY_DATE, "codes");

    /** The keys a Code in a DrivingPrivilege's codes may have (7.2.4); code is required. */
    public static final Set<String> DRIVING_PRIVILEGE_CODE_KEYS = Set.of("code", "sign", "value");

    /** Elements encoded as a byte string; a template carries them as base64 text. */
    public static final Set<String> BYTE_STRING = Set.of("portrait", "signature_usual_mark");

    /** biometric_template_xx, where xx names the biometric type (7.2.7), is a byte string too. */
    public static final String BIOMETRIC_TEMPLATE_PREFIX = "biometric_template_";

    private MdlDataElements() {
    }

    /** The mandatory elements missing from the given identifiers, in Table 5 order. */
    public static List<String> missingMandatory(Collection<String> identifiers) {
        return MANDATORY.stream().filter(element -> !identifiers.contains(element)).toList();
    }

    /** Whether Table 5 encodes the element as a byte string. */
    public static boolean isByteString(String identifier) {
        return identifier != null
                && (BYTE_STRING.contains(identifier) || identifier.startsWith(BIOMETRIC_TEMPLATE_PREFIX));
    }
}
