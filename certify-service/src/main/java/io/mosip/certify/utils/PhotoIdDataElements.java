package io.mosip.certify.utils;

import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * What ISO/IEC TS 23220-2 says about the data elements of a Photo ID (ISO/IEC TS 23220-4), in the one
 * place the processor and the credential configuration validator both read it from.
 */
public final class PhotoIdDataElements {

    /** The Photo ID document type. */
    public static final String DOC_TYPE = "org.iso.23220.photoid.1";

    /** The namespace of the generic ISO/IEC TS 23220-2 data elements, which carries the Photo ID's core elements. */
    public static final String NAMESPACE = "org.iso.23220.1";

    /** A byte string (ISO/IEC TS 23220-4, Annex C, Table 1); Certify requires a JPEG or JPEG2000 image, as for the mDL. */
    public static final String PORTRAIT = "portrait";

    public static final String ISSUE_DATE = "issue_date";

    public static final String EXPIRY_DATE = "expiry_date";

    public static final String PORTRAIT_CAPTURE_DATE = "portrait_capture_date";

    /**
     * A full-date, or a map holding a full-date under the same key, birth_date, and an optional
     * approximate_mask (ISO/IEC TS 23220-2, 6.3.1.1.3).
     */
    public static final String BIRTH_DATE = "birth_date";

    /** Eight digits, each 0 or 1, marking which of the birth date's YYYYMMDD digits are unknown. */
    public static final String APPROXIMATE_MASK = "approximate_mask";

    /** The keys a birth_date map may have; birth_date is required. */
    public static final Set<String> BIRTH_DATE_KEYS = Set.of(BIRTH_DATE, APPROXIMATE_MASK);

    public static final String AGE_OVER_18 = "age_over_18";

    /** Age attestations, age_over_00 to age_over_99, each a boolean (ISO/IEC TS 23220-2, 6.3.2.2). */
    private static final Pattern AGE_OVER_NN = Pattern.compile("age_over_\\d{2}");

    /** Elements every Photo ID must carry in this namespace (ISO/IEC TS 23220-4, Annex C, Table C.1, presence "M"). */
    public static final List<String> MANDATORY = List.of(
            "family_name", "given_name", BIRTH_DATE, PORTRAIT, ISSUE_DATE, EXPIRY_DATE,
            "issuing_authority", "issuing_country", AGE_OVER_18);

    /** Elements encoded as a byte string; a template carries them as base64 text. */
    public static final Set<String> BYTE_STRING = Set.of(PORTRAIT);

    /** Elements whose value must be a full-date (CBOR tag 1004); unlike the mDL, never a date-time. */
    public static final Set<String> FULL_DATE = Set.of(ISSUE_DATE, EXPIRY_DATE);

    /** Elements whose value must be a date-time, a tdate (CBOR tag 0). */
    public static final Set<String> TDATE = Set.of(PORTRAIT_CAPTURE_DATE);

    private PhotoIdDataElements() {
    }

    /** The mandatory elements missing from the given identifiers, in Table C.1 order. */
    public static List<String> missingMandatory(Collection<String> identifiers) {
        return MANDATORY.stream().filter(element -> !identifiers.contains(element)).toList();
    }

    /** Whether the element is an age attestation, age_over_NN, whose value is a boolean. */
    public static boolean isAgeOver(String identifier) {
        return identifier != null && AGE_OVER_NN.matcher(identifier).matches();
    }

    /** Whether ISO/IEC TS 23220-2 encodes the element as a byte string. */
    public static boolean isByteString(String identifier) {
        return BYTE_STRING.contains(identifier);
    }
}
