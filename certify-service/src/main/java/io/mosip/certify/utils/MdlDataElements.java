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

    public static final String BIRTH_DATE = "birth_date";

    public static final String ISSUE_DATE = "issue_date";

    public static final String EXPIRY_DATE = "expiry_date";

    /** Must be a JPEG or JPEG2000 image (7.2.2). */
    public static final String PORTRAIT = "portrait";

    /** The keys of a DrivingPrivilege (7.2.4), besides issue_date and expiry_date. */
    public static final String VEHICLE_CATEGORY_CODE = "vehicle_category_code";

    public static final String CODES = "codes";

    /** The keys of a Code in a DrivingPrivilege's codes (7.2.4). */
    public static final String CODE = "code";

    public static final String CODE_SIGN = "sign";

    public static final String CODE_VALUE = "value";

    /** Elements every mDL must carry (Table 5, presence "M"). */
    public static final List<String> MANDATORY = List.of(
            "family_name", "given_name", BIRTH_DATE, ISSUE_DATE, EXPIRY_DATE,
            "issuing_country", "issuing_authority", "document_number", PORTRAIT,
            DRIVING_PRIVILEGES, "un_distinguishing_sign");

    private static final Set<String> ISSUE_AND_EXPIRY_DATES = Set.of(ISSUE_DATE, EXPIRY_DATE);

    /** Top-level elements whose value must be a full-date (CBOR tag 1004). */
    public static final Set<String> FULL_DATE = Set.of(BIRTH_DATE);

    /** Top-level elements whose value is a full-date (tag 1004) or a date-time, a tdate (tag 0). */
    public static final Set<String> FULL_DATE_OR_TDATE = ISSUE_AND_EXPIRY_DATES;

    /** The dates inside each driving_privileges entry, full-dates only (7.2.4). */
    public static final Set<String> DRIVING_PRIVILEGE_FULL_DATE = ISSUE_AND_EXPIRY_DATES;

    /** The keys a DrivingPrivilege may have (7.2.4); vehicle_category_code is required. */
    public static final Set<String> DRIVING_PRIVILEGE_KEYS = Set.of(VEHICLE_CATEGORY_CODE, ISSUE_DATE, EXPIRY_DATE, CODES);

    /** The keys a Code in a DrivingPrivilege's codes may have (7.2.4); code is required. */
    public static final Set<String> DRIVING_PRIVILEGE_CODE_KEYS = Set.of(CODE, CODE_SIGN, CODE_VALUE);

    /** Elements encoded as a byte string; a template carries them as base64 text. */
    public static final Set<String> BYTE_STRING = Set.of(PORTRAIT, "signature_usual_mark");

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
