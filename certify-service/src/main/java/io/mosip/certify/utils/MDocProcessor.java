package io.mosip.certify.utils;

import co.nstant.in.cbor.CborDecoder;
import co.nstant.in.cbor.CborEncoder;
import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.model.*;

import java.io.ByteArrayOutputStream;

import io.mosip.certify.config.MDocConfig;
import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.constants.VCDM2Constants;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.kernel.keymanagerservice.service.KeymanagerService;
import io.mosip.kernel.signature.dto.CoseSignRequestDto;
import io.mosip.kernel.signature.service.CoseSignatureService;
import lombok.extern.slf4j.Slf4j;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.LocalDate;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.Map;
import java.util.regex.Pattern;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Utility class for mDoc (Mobile Document) specific operations.
 * Provides helper methods for mDoc structure creation and manipulation.
 */
@Slf4j
@Component
public class MDocProcessor {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    /**
     * ISO/IEC 18013-5: ValidityInfo timestamps shall not use fractions of seconds
     * and shall use a UTC offset of 00:00, as indicated by the character "Z".
     */
    private static final DateTimeFormatter VALIDITY_INFO_DATETIME_FORMATTER =
            DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'");

    /** The digest algorithms an MSO may use (ISO/IEC 18013-5, 9.1.2.5). */
    public static final Set<String> SUPPORTED_DIGEST_ALGORITHMS = Set.of("SHA-256", "SHA-384", "SHA-512");

    /** The CBOR tag of a full-date (RFC 8943). */
    private static final int FULL_DATE_TAG = 1004;

    /** The CBOR tag of a tdate, an RFC 3339 date-time (RFC 8949). */
    private static final int TDATE_TAG = 0;

    /**
     * A whole value that is a Velocity reference such as ${familyName}, $familyName, $!{familyName} or
     * ${holder.familyName}. Velocity renders a reference to a missing value as this text.
     */
    private static final Pattern UNRENDERED_REFERENCE =
            Pattern.compile("\\$!?(\\{[A-Za-z][\\w.-]*}|[A-Za-z][\\w.-]*)");

    private final ObjectMapper objectMapper;

    private final MDocConfig mDocConfig;

    private final CoseSignatureService coseSignatureService;

    private final KeymanagerService keymanagerService;

    /** The keys keymanager's COSE signer signs with when the request has no application ID. */
    @Value("${mosip.sign.applicationid:KERNEL}")
    private String defaultSignApplicationId;

    @Value("${mosip.sign.refid:SIGN}")
    private String defaultSignReferenceId;

    public MDocProcessor(ObjectMapper objectMapper,
                         MDocConfig mDocConfig,
                         CoseSignatureService coseSignatureService,
                         KeymanagerService keymanagerService) {
        this.objectMapper = objectMapper;
        this.mDocConfig = mDocConfig;
        this.coseSignatureService = coseSignatureService;
        this.keymanagerService = keymanagerService;
    }

    /**
     * The notBefore of the certificate that signing with this key puts in the MSO header (x5chain):
     * keymanager signs with the key's current certificate, which getCertificate returns.
     */
    public ZonedDateTime signingCertificateNotBefore(String appID, String refID) throws CertificateException {
        // The COSE signer uses its configured keys when the application ID is blank, so the lookup
        // does the same to read the certificate it will sign with.
        if (appID == null || appID.isBlank()) {
            appID = defaultSignApplicationId;
            refID = defaultSignReferenceId;
        }
        String certificatePem = keymanagerService.getCertificate(appID, Optional.of(refID)).getCertificate();
        X509Certificate certificate = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(certificatePem.getBytes(StandardCharsets.UTF_8)));
        return certificate.getNotBefore().toInstant().atZone(ZoneOffset.UTC);
    }

    /**
     * Process templated JSON to create final mDoc structure. signingCertificateNotBefore is the
     * notBefore of the certificate the MSO will be signed with; validityInfo.signed is not set
     * before it.
     */
    public Map<String, Object> processTemplatedJson(String templatedJSON, Map<String, Object> templateParams,
                                                    ZonedDateTime signingCertificateNotBefore) {
        try {
            JsonNode templateNode = objectMapper.readTree(templatedJSON);
            Map<String, Object> finalMDoc = new HashMap<>();

            JsonNode validityInfo = Objects.requireNonNull(
                    templateNode.get(Constants.VALIDITY_INFO),
                    "Missing validity info"
            );

            Map<String, Object> validity = objectMapper.convertValue(validityInfo, Map.class);

            String validFromValue = Objects.requireNonNull(
                    (String) validity.get(VCDM2Constants.VALID_FROM),
                    "Missing validFrom"
            );
            String signedValue = Objects.requireNonNull(
                    (String) validity.get(Constants.SIGNED),
                    "Missing signed"
            );
            String validUntilValue = Objects.requireNonNull(
                    (String) validity.get(VCDM2Constants.VALID_UNTIL),
                    "Missing validUntil"
            );

            // ISO/IEC 18013-5, 9.1.2.4: Certify sets the validityInfo dates, so the template must leave
            // each one as its placeholder.
            requirePlaceholder(Constants.SIGNED, signedValue, "${_signed}");
            requirePlaceholder(VCDM2Constants.VALID_FROM, validFromValue, "${_validFrom}");
            requirePlaceholder(VCDM2Constants.VALID_UNTIL, validUntilValue, "${_validUntil}");

            if (templateParams.containsKey(Constants.DID_URL)) {
                finalMDoc.put("_issuer", templateParams.get(Constants.DID_URL));
            }
            String docType = Objects.requireNonNull(templateNode.get(Constants.DOCTYPE), "Missing docType").asText();
            finalMDoc.put("_docType", docType);
            if (templateParams.containsKey(Constants._HOLDER_ID)) {
                finalMDoc.put(Constants._HOLDER_ID, templateParams.get(Constants._HOLDER_ID));
            }

            // Process namespaces
            Map<String, Object> nameSpaces = new HashMap<>();

            if (templateNode.has(Constants.NAMESPACES)) {
                JsonNode nameSpacesNode = templateNode.get(Constants.NAMESPACES);
                nameSpacesNode.fieldNames().forEachRemaining(namespaceName -> {
                    JsonNode namespaceItems = nameSpacesNode.get(namespaceName);
                    List<Map<String, Object>> processedItems = processNamespaceItems(namespaceItems);
                    nameSpaces.put(namespaceName, processedItems);
                });
            }
            finalMDoc.put(Constants.NAMESPACES, nameSpaces);
            if (MdlDataElements.DOC_TYPE.equals(docType)) {
                requireMandatoryMdlElements(nameSpaces);
            }

            // ISO/IEC 18013-5, 9.1.2.4: the timestamps "should" have a precision that limits
            // linkability, so they are the start of the UTC day of issuance rather than the exact
            // time. signed is not before the signing certificate's notBefore, though: it must fall
            // within the validity of the certificate in the MSO header (9.3.1), and on the day a
            // signing key is generated or rotated its certificate starts after 00:00:00Z. Every mDL
            // signed with that certificate on that day still gets the same value. validFrom is not
            // before signed or the mDL issue_date (7.2.1) and validUntil is validityPeriodYears
            // (at least 1) after validFrom, so signed <= validFrom < validUntil.
            ZonedDateTime signed = ZonedDateTime.now(ZoneOffset.UTC).truncatedTo(ChronoUnit.DAYS);
            if (signingCertificateNotBefore.isAfter(signed)) {
                signed = signingCertificateNotBefore.withZoneSameInstant(ZoneOffset.UTC);
            }
            ZonedDateTime validFrom = signed;
            ZonedDateTime issueDateStart = mdlIssueDateStart(nameSpaces);
            if (issueDateStart != null && issueDateStart.isAfter(validFrom)) {
                validFrom = issueDateStart;
            }
            ZonedDateTime validUntil = validFrom.plusYears(mDocConfig.getValidityPeriodYears());

            validity.put(Constants.SIGNED, createCBORTaggedDateTime(signed.format(VALIDITY_INFO_DATETIME_FORMATTER)));
            validity.put(VCDM2Constants.VALID_FROM, createCBORTaggedDateTime(validFrom.format(VALIDITY_INFO_DATETIME_FORMATTER)));
            validity.put(VCDM2Constants.VALID_UNTIL, createCBORTaggedDateTime(validUntil.format(VALIDITY_INFO_DATETIME_FORMATTER)));

            finalMDoc.put(Constants.VALIDITY_INFO, validity);

            return finalMDoc;

        } catch (CertifyException e) {
            throw e;
        } catch (Exception e) {
            log.error("Error processing templated JSON: {}", e.getMessage(), e);
            throw new CertifyException(ErrorConstants.MDOC_TEMPLATE_PROCESSING_FAILED, "Error processing templated JSON: " + e.getMessage());
        }
    }

    /**
     * The earliest validFrom the mDL issue_date allows (7.2.1), or null when there is none. Table 5
     * allows a full-date or a tdate: a full-date gives the start of that day, and a date-time gives
     * the next 00:00:00Z at or after it, so validFrom keeps the precision of a day. The value may be
     * plain or already tagged by the template (1004 or 0).
     */
    private static ZonedDateTime mdlIssueDateStart(Map<String, Object> nameSpaces) {
        Object items = nameSpaces.get(MdlDataElements.NAMESPACE);
        if (!(items instanceof List<?> elements)) {
            return null;
        }
        for (Object element : elements) {
            if (element instanceof Map<?, ?> item
                    && MdlDataElements.ISSUE_DATE.equals(item.get(Constants.ELEMENT_IDENTIFIER))) {
                return startOfDayAtOrAfter(untagDate(item.get(Constants.ELEMENT_VALUE)));
            }
        }
        return null;
    }

    /** The value inside a full-date (1004) or tdate (0) tag the template wrote, or the value itself. */
    private static Object untagDate(Object value) {
        if (value instanceof Map<?, ?> tagged) {
            Object tag = tagged.get(Constants.__CBOR_TAG);
            if (Integer.valueOf(FULL_DATE_TAG).equals(tag) || Integer.valueOf(TDATE_TAG).equals(tag)) {
                return tagged.get(Constants.__CBOR_VALUE);
            }
        }
        return value;
    }

    /**
     * The start of a full-date, or the next 00:00:00Z at or after a date-time, or null when the
     * value is neither.
     */
    private static ZonedDateTime startOfDayAtOrAfter(Object value) {
        if (!(value instanceof String text)) {
            return null;
        }
        if (isDateOnlyString(text)) {
            return LocalDate.parse(text, DateTimeFormatter.ISO_LOCAL_DATE).atStartOfDay(ZoneOffset.UTC);
        }
        ZonedDateTime dateTime = parseDateTime(text);
        if (dateTime == null) {
            return null;
        }
        ZonedDateTime startOfDay = dateTime.truncatedTo(ChronoUnit.DAYS);
        return startOfDay.equals(dateTime) ? startOfDay : startOfDay.plusDays(1);
    }

    /** An RFC 3339 date-time in UTC without fractions of seconds, or null when the text is not one. */
    private static ZonedDateTime parseDateTime(String text) {
        try {
            return OffsetDateTime.parse(text, DateTimeFormatter.ISO_OFFSET_DATE_TIME)
                    .atZoneSameInstant(ZoneOffset.UTC).truncatedTo(ChronoUnit.SECONDS);
        } catch (DateTimeParseException e) {
            return null;
        }
    }

    /**
     * ISO/IEC 18013-5, 7.2.1 (Table 5): the rendered mDL must carry every mandatory element in the
     * org.iso.18013.5.1 namespace. The configuration check can't see a template whose elements are
     * only known after Velocity renders it, so the rendered mDL is checked here before it is signed.
     * A mandatory element must also have a value: not null, not empty, and not a template reference that
     * Velocity left as it is because the data provider did not supply it; the same goes for every value
     * inside a structured one such as driving_privileges.
     */
    private static void requireMandatoryMdlElements(Map<String, Object> nameSpaces) {
        Set<String> identifiers = new HashSet<>();
        if (nameSpaces.get(MdlDataElements.NAMESPACE) instanceof List<?> elements) {
            for (Object element : elements) {
                if (element instanceof Map<?, ?> item && item.get(Constants.ELEMENT_IDENTIFIER) instanceof String identifier) {
                    if (MdlDataElements.MANDATORY.contains(identifier)) {
                        Object elementValue = item.get(Constants.ELEMENT_VALUE);
                        if (elementValue == null) {
                            throw new CertifyException(ErrorConstants.MDL_MANDATORY_ELEMENTS_MISSING,
                                    "An mDL mandatory element has a null value: " + identifier + ".");
                        }
                        if (elementValue instanceof String s && UNRENDERED_REFERENCE.matcher(s).matches()) {
                            throw new CertifyException(ErrorConstants.MDL_MANDATORY_ELEMENTS_MISSING,
                                    "An mDL mandatory element has no value: " + identifier + " is the template reference "
                                            + s + ", which the data provider did not supply.");
                        }
                        if (elementValue instanceof String s && s.isBlank()) {
                            throw new CertifyException(ErrorConstants.MDL_MANDATORY_ELEMENTS_MISSING,
                                    "An mDL mandatory element has an empty value: " + identifier + ".");
                        }
                        String nestedMissing = findMissingNestedValue(elementValue);
                        if (nestedMissing != null) {
                            throw new CertifyException(ErrorConstants.MDL_MANDATORY_ELEMENTS_MISSING,
                                    "An mDL mandatory element has no value: " + identifier + " contains " + nestedMissing + ".");
                        }
                    }
                    if (!identifiers.add(identifier)) {
                        throw new CertifyException(ErrorConstants.MDOC_TEMPLATE_PROCESSING_FAILED,
                                "Duplicate mDL element identifier: " + identifier + ".");
                    }
                }
            }
        }
        List<String> missing = MdlDataElements.missingMandatory(identifiers);
        if (!missing.isEmpty()) {
            log.error("The rendered mDL lacks the ISO/IEC 18013-5 mandatory elements {}", missing);
            throw new CertifyException(ErrorConstants.MDL_MANDATORY_ELEMENTS_MISSING,
                    "An mDL must contain every ISO/IEC 18013-5 mandatory element in the org.iso.18013.5.1 namespace. Missing: "
                            + String.join(", ", missing) + ".");
        }
    }

    /**
     * Describes the first value missing inside a structured element such as driving_privileges: a null,
     * an empty string, or a template reference Velocity left as it is. Null when every value is there,
     * and for a value that isn't a map or a list (the caller checks those itself).
     */
    private static String findMissingNestedValue(Object value) {
        Collection<?> children;
        if (value instanceof Map<?, ?> map) {
            children = map.values();
        } else if (value instanceof List<?> list) {
            children = list;
        } else {
            return null;
        }
        for (Object child : children) {
            if (child == null) {
                return "a null value";
            }
            if (child instanceof String text) {
                if (UNRENDERED_REFERENCE.matcher(text).matches()) {
                    return "the template reference " + text + ", which the data provider did not supply";
                }
                if (text.isBlank()) {
                    return "an empty value";
                }
            }
            String missing = findMissingNestedValue(child);
            if (missing != null) {
                return missing;
            }
        }
        return null;
    }

    /** A validityInfo date written out in the template is refused: only its placeholder is accepted. */
    private static void requirePlaceholder(String name, String value, String placeholder) {
        if (!placeholder.equals(value)) {
            throw new IllegalArgumentException("validityInfo." + name + " must be " + placeholder
                    + "; Certify sets the validityInfo dates at issuance");
        }
    }

    /**
     * Process items within a namespace
     */
    private List<Map<String, Object>> processNamespaceItems(JsonNode namespaceItems) {
        List<Map<String, Object>> processedItems = new ArrayList<>();
        // ISO/IEC 18013-5, 9.1.2.4: digestIDs are unique within a namespace and are drawn at random,
        // so the same element cannot be recognised by its ID across credentials. Any digestID in the
        // template is therefore ignored.
        Set<Integer> usedDigestIds = new HashSet<>();

        // First, add all items from template
        for (JsonNode item : namespaceItems) {
            Map<String, Object> itemMap = new HashMap<>();
            int digestId;
            do {
                digestId = SECURE_RANDOM.nextInt(Integer.MAX_VALUE);
            } while (!usedDigestIds.add(digestId));
            itemMap.put(Constants.DIGEST_ID, digestId);
            itemMap.put(Constants.ELEMENT_IDENTIFIER, item.get(Constants.ELEMENT_IDENTIFIER).asText());

            // Handle elementValue which could be string or complex object
            JsonNode elementValue = item.get(Constants.ELEMENT_VALUE);
            if (elementValue.isTextual()) {
                itemMap.put(Constants.ELEMENT_VALUE, elementValue.asText());
            } else {
                // Convert complex objects (like driving_privileges)
                Object value = objectMapper.convertValue(elementValue, Object.class);
                itemMap.put(Constants.ELEMENT_VALUE, value);
            }

            processedItems.add(itemMap);
        }

        return processedItems;
    }

    /**
     * Adds random salts to each data element
     */
    public static Map<String, Object> addRandomSalts(Map<String, Object> mDocJson) {
        Map<String, Object> nameSpaces = (Map<String, Object>) mDocJson.get(Constants.NAMESPACES);
        Map<String, Object> saltedNamespaces = new HashMap<>();

        for (Map.Entry<String, Object> namespaceEntry : nameSpaces.entrySet()) {
            String namespaceName = namespaceEntry.getKey();
            List<Map<String, Object>> elements = (List<Map<String, Object>>) namespaceEntry.getValue();

            List<Map<String, Object>> saltedElements = new ArrayList<>();

            for (Map<String, Object> element : elements) {
                // Generate 24-byte random salt
                byte[] randomSalt = new byte[24];
                SECURE_RANDOM.nextBytes(randomSalt);

                // Clone element with random salt as hex string
                Map<String, Object> saltedElement = new HashMap<>(element);
                saltedElement.put("random", randomSalt);

                saltedElements.add(saltedElement);
            }

            saltedNamespaces.put(namespaceName, saltedElements);
        }

        return saltedNamespaces;
    }

    /** The digest algorithm the MSO declares, which calculateDigests must also use. */
    public String getDigestAlgorithm() {
        return mDocConfig.getDigestAlgorithm();
    }

    /**
     * Calculates the digest of each salted element with the given algorithm, which must be the one
     * the MSO declares.
     */
    public static Map<String, Object> calculateDigests
    (Map<String, Object> saltedNamespaces, Map<String, Map<Integer, byte[]>> namespaceDigests,
     String digestAlgorithm) throws Exception {
        if (!SUPPORTED_DIGEST_ALGORITHMS.contains(digestAlgorithm)) {
            throw new IllegalArgumentException("Unsupported MSO digest algorithm: " + digestAlgorithm);
        }

        Map<String, Object> taggedNamespaces = new HashMap<>();

        for (Map.Entry<String, Object> namespaceEntry : saltedNamespaces.entrySet()) {
            String namespaceName = namespaceEntry.getKey();
            List<Map<String, Object>> elements = (List<Map<String, Object>>) namespaceEntry.getValue();

            List<Object> taggedElements = new ArrayList<>();
            Map<Integer, byte[]> digestMap = new HashMap<>();

            for (Map<String, Object> element : elements) {
                // 1) Encode element (IssuerSignedItem) to CBOR
                ByteArrayOutputStream innerBaos = new ByteArrayOutputStream();
                new CborEncoder(innerBaos).encode(convertToDataItem(preprocessForCBOR(encodeMdlElement(namespaceName, element))));
                byte[] elementCbor = innerBaos.toByteArray();

                // 2) Build Tag(24) DataItem for final structure
                ByteString tag24Value = new ByteString(elementCbor);
                tag24Value.setTag(24);
                taggedElements.add(tag24Value);

                // 3) Calculate digest over Tag(24) encoded bytes
                ByteArrayOutputStream outerBaos = new ByteArrayOutputStream();
                new CborEncoder(outerBaos).encode(tag24Value);
                byte[] taggedCbor = outerBaos.toByteArray();
                byte[] digest = MessageDigest.getInstance(digestAlgorithm).digest(taggedCbor);
                digestMap.put((Integer) element.get(Constants.DIGEST_ID), digest);
            }

            taggedNamespaces.put(namespaceName, taggedElements);
            namespaceDigests.put(namespaceName, digestMap);
        }

        return taggedNamespaces;
    }

    /**
     * Applies the Table 5 encodings to an element of the mDL namespace: a date-only value of a
     * full-date element, including the dates inside each driving privilege, becomes tag 1004, and a
     * byte-string element is decoded from the base64 text the template carries. Elements of any
     * other namespace are left as they are; a template tags them explicitly if it needs to.
     */
    private static Map<String, Object> encodeMdlElement(String namespace, Map<String, Object> element) {
        if (!MdlDataElements.NAMESPACE.equals(namespace)) {
            return element;
        }
        String identifier = (String) element.get(Constants.ELEMENT_IDENTIFIER);
        Object value = element.get(Constants.ELEMENT_VALUE);
        Object encoded = value;
        if (MdlDataElements.FULL_DATE_OR_TDATE.contains(identifier)) {
            encoded = asFullDateOrTdate(value);
        } else if (MdlDataElements.FULL_DATE.contains(identifier)) {
            encoded = asFullDate(value);
        } else if (MdlDataElements.isByteString(identifier)) {
            // Values come from the templated JSON, so a byte string can only arrive as base64 text.
            if (!(value instanceof String text)) {
                throw new IllegalArgumentException(identifier + " must be base64 encoded");
            }
            encoded = decodeBase64(identifier, text);
        } else if (MdlDataElements.DRIVING_PRIVILEGES.equals(identifier)) {
            if (!(value instanceof List<?> privileges)) {
                throw new IllegalArgumentException("driving_privileges must be an array");
            }
            List<Object> encodedPrivileges = new ArrayList<>();
            for (Object privilege : privileges) {
                if (privilege instanceof Map<?, ?> fields) {
                    Map<Object, Object> encodedFields = new HashMap<>(fields);
                    for (String dateField : MdlDataElements.DRIVING_PRIVILEGE_FULL_DATE) {
                        if (encodedFields.containsKey(dateField)) {
                            encodedFields.put(dateField, asFullDate(encodedFields.get(dateField)));
                        }
                    }
                    encodedPrivileges.add(encodedFields);
                } else {
                    encodedPrivileges.add(privilege);
                }
            }
            encoded = encodedPrivileges;
        }
        if (encoded == value) {
            return element;
        }
        Map<String, Object> encodedElement = new HashMap<>(element);
        encodedElement.put(Constants.ELEMENT_VALUE, encoded);
        return encodedElement;
    }

    private static Object asFullDate(Object value) {
        if (value instanceof String text) {
            if (!isDateOnlyString(text)) {
                throw new IllegalArgumentException("Invalid mDL full-date: " + text);
            }
            return createCBORTaggedDate(text);
        }
        return value;
    }

    /**
     * Table 5: issue_date and expiry_date are a full-date or a tdate. A date-time becomes a tdate
     * (tag 0) in UTC without fractions of seconds; anything else is handled as a full-date.
     */
    private static Object asFullDateOrTdate(Object value) {
        if (value instanceof String text && !isDateOnlyString(text)) {
            ZonedDateTime dateTime = parseDateTime(text);
            if (dateTime != null) {
                return createCBORTaggedDateTime(dateTime.format(VALIDITY_INFO_DATETIME_FORMATTER));
            }
        }
        return asFullDate(value);
    }

    /**
     * Accepts base64 and base64url, with or without padding, alone or as a base64 data URI
     * (data:image/jpeg;base64,...), the form identity sources keep photos in.
     */
    private static byte[] decodeBase64(String identifier, String text) {
        String base64 = text.trim();
        int comma = base64.indexOf(',');
        if (base64.startsWith("data:") && comma > 0 && base64.substring(0, comma).endsWith(";base64")) {
            base64 = base64.substring(comma + 1);
        }
        try {
            return Base64.getDecoder().decode(base64.replace('-', '+').replace('_', '/'));
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(identifier + " must be base64 encoded");
        }
    }

    public static byte[] encodeToCBOR(Object obj) throws Exception {
        try {
            Object preprocessedData = preprocessForCBOR(obj);
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            CborEncoder encoder = new CborEncoder(baos);
            encoder.encode(convertToDataItem(preprocessedData));
            return baos.toByteArray();
        } catch (Exception e) {
            log.error("Error encoding to CBOR: {}", e.getMessage(), e);
            throw new Exception("CBOR encoding failed: " + e.getMessage(), e);
        }
    }

    public static byte[] encodeToTaggedCBOR(Object obj) throws Exception {
        try {
            byte[] innerCborBytes = encodeToCBOR(obj);

            // Format: #6.24(bstr .cbor convertToDataItem(preprocessedData))
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            CborEncoder encoder = new CborEncoder(baos);
            ByteString taggedCbor = new ByteString(innerCborBytes);
            taggedCbor.setTag(24);
            encoder.encode(taggedCbor);

            return baos.toByteArray();
        } catch (Exception e) {
            log.error("Error encoding to CBOR: {}", e.getMessage(), e);
            throw new Exception("CBOR encoding failed: " + e.getMessage(), e);
        }
    }

    /**
     * Preprocesses objects for CBOR encoding (handles dates, byte arrays, etc.)
     */
    private static Object preprocessForCBOR(Object obj) {
        if (obj == null) {
            return null;
        }

        // Handle byte arrays directly - don't convert to hex
        if (obj instanceof byte[]) {
            return obj;
        }

        if (obj instanceof Map) {
            Map<Object, Object> map = (Map<Object, Object>) obj;
            Map<Object, Object> processedMap = new HashMap<>();

            for (Map.Entry<Object, Object> entry : map.entrySet()) {
                Object processedKey = preprocessForCBOR(entry.getKey());
                Object processedValue = preprocessForCBOR(entry.getValue());
                processedMap.put(processedKey, processedValue);
            }
            return processedMap;
        }

        if (obj instanceof List) {
            List<Object> list = (List<Object>) obj;
            List<Object> processedList = new ArrayList<>();
            for (Object item : list) {
                processedList.add(preprocessForCBOR(item));
            }
            return processedList;
        }

        return obj; // Return as-is for primitives
    }

    private static DataItem convertToDataItem(Object obj) {
        if (obj instanceof DataItem di) {
            return di;
        }
        if (obj == null) {
            return SimpleValue.NULL;
        }
        if (obj instanceof String) {
            return new UnicodeString((String) obj);
        }
        if (obj instanceof Integer) {
            int value = (Integer) obj;
            if (value < 0) {
                return new NegativeInteger(value);
            } else {
                return new UnsignedInteger(value);
            }
        }
        if (obj instanceof Long) {
            long value = (Long) obj;
            if (value < 0) {
                return new NegativeInteger(value);
            } else {
                return new UnsignedInteger(value);
            }
        }
        if (obj instanceof Boolean) {
            return (Boolean) obj ? SimpleValue.TRUE : SimpleValue.FALSE;
        }
        if (obj instanceof Double) {
            return new DoublePrecisionFloat((Double) obj);
        }
        if (obj instanceof Float) {
            return new SinglePrecisionFloat((Float) obj);
        }
        if (obj instanceof byte[]) {
            return new ByteString((byte[]) obj);
        }
        if (obj instanceof java.util.Map && ((java.util.Map<?, ?>) obj).containsKey(Constants.__CBOR_TAG)) {
            java.util.Map<?, ?> taggedMap = (java.util.Map<?, ?>) obj;
            int tag = (Integer) taggedMap.get(Constants.__CBOR_TAG);
            Object value = taggedMap.get(Constants.__CBOR_VALUE);
            DataItem dataItem = convertToDataItem(value);
            dataItem.setTag(tag);  // This correctly sets the tag
            return dataItem;
        }
        if (obj instanceof java.util.Map) {
            co.nstant.in.cbor.model.Map map = new co.nstant.in.cbor.model.Map();
            for (Object entry : ((java.util.Map<?, ?>) obj).entrySet()) {
                java.util.Map.Entry<?, ?> mapEntry = (java.util.Map.Entry<?, ?>) entry;
                DataItem keyItem = convertToDataItem(mapEntry.getKey());
                DataItem valueItem = convertToDataItem(mapEntry.getValue());
                map.put(keyItem, valueItem);
            }
            return map;
        }
        if (obj instanceof List) {
            Array array = new Array();
            for (Object item : (List<?>) obj) {
                array.add(convertToDataItem(item));
            }
            return array;
        }
        // For any other type, convert to string
        return new UnicodeString(obj.toString());
    }


    /**
     * Checks if a string represents a date-only value (YYYY-MM-DD)
     */
    private static boolean isDateOnlyString(String str) {
        try {
            LocalDate.parse(str, DateTimeFormatter.ISO_LOCAL_DATE);
            return str.matches("\\d{4}-\\d{2}-\\d{2}");
        } catch (DateTimeParseException e) {
            return false;
        }
    }

    /**
     * Creates a CBOR tagged date (tag 1004) for date-only strings
     */
    private static Map<String, Object> createCBORTaggedDate(String dateStr) {
        Map<String, Object> taggedDate = new HashMap<>();
        taggedDate.put(Constants.__CBOR_TAG, FULL_DATE_TAG);
        taggedDate.put(Constants.__CBOR_VALUE, dateStr);
        return taggedDate;
    }

    /**
     * Creates a CBOR tagged datetime (tag 0) for datetime strings (RFC 3339 format)
     * RFC 8610: tdate = #6.0(tstr) where tstr = #3
     * This wraps full datetime timestamps in Tag 0 as per mso_mdoc specification
     */
    private static Map<String, Object> createCBORTaggedDateTime(String dateTimeStr) {
        Map<String, Object> taggedDate = new HashMap<>();
        taggedDate.put(Constants.__CBOR_TAG, 0);
        taggedDate.put(Constants.__CBOR_VALUE, dateTimeStr);
        return taggedDate;
    }

    /**
     * Creates the Mobile Security Object (MSO) structure
     */
    public Map<String, Object> createMobileSecurityObject
    (Map<String, Object> mDocJson, Map<String, Map<Integer, byte[]>> namespaceDigests) throws Exception {

        Map<String, Object> mso = new HashMap<>();
        mso.put("version", mDocConfig.getMsoVersion());
        mso.put("digestAlgorithm", mDocConfig.getDigestAlgorithm());

        // Create valueDigests structure
        Map<String, Object> nameSpacesDigests = new HashMap<>();
        nameSpacesDigests.putAll(namespaceDigests);

        mso.put("valueDigests", nameSpacesDigests);
        mso.put(Constants.DOCTYPE, mDocJson.get("_docType"));

        // Create validity info with current timestamp
        Map<String, Object> validityInfo = new HashMap<>();

        if (mDocJson.containsKey(Constants.VALIDITY_INFO)) {
            Map<String, Object> originalValidity = (Map<String, Object>) mDocJson.get(Constants.VALIDITY_INFO);
            validityInfo.put(VCDM2Constants.VALID_FROM, originalValidity.get(VCDM2Constants.VALID_FROM));
            validityInfo.put(VCDM2Constants.VALID_UNTIL, originalValidity.get(VCDM2Constants.VALID_UNTIL));
            validityInfo.put(Constants.SIGNED, originalValidity.get(Constants.SIGNED));
        }
        mso.put(Constants.VALIDITY_INFO, validityInfo);

        // Add device key info (placeholder - should be from wallet's PoP)
        Map<String, Object> deviceKeyInfo = createDeviceKeyInfo(mDocJson.get(Constants._HOLDER_ID));
        mso.put("deviceKeyInfo", deviceKeyInfo);

        return mso;
    }

    /**
     * Creates device key info structure (placeholder implementation)
     */
    private static Map<String, Object> createDeviceKeyInfo(Object deviceInfo) throws Exception {
        if (deviceInfo == null) {
            throw new IllegalArgumentException("Device info (holder ID) is required for mDoc credential");
        }
        String deviceKeyEncoded = deviceInfo.toString();
        if (deviceKeyEncoded.startsWith(Constants.DID_JWK_PREFIX)) {
            deviceKeyEncoded = deviceKeyEncoded.substring(Constants.DID_JWK_PREFIX.length());
            // Drop the DID URL fragment (#0 or any other): it selects a verification method and is
            // not part of the encoded key. replace("#0", "") missed other fragments and could also
            // remove "#0" from the middle of the value.
            int fragment = deviceKeyEncoded.indexOf('#');
            if (fragment >= 0) {
                deviceKeyEncoded = deviceKeyEncoded.substring(0, fragment);
            }
        }

        byte[] decodedBytes = Base64.getUrlDecoder().decode(deviceKeyEncoded);
        String decodedJson = new String(decodedBytes);

        ObjectMapper mapper = new ObjectMapper();
        Map<String, Object> jwk = mapper.readValue(decodedJson, Map.class);

        Map<Object, Object> coseKey = new HashMap<>();
        coseKey.put(1, 2);  // kty: EC2
        coseKey.put(3, -7); // alg: ES256 (ECDSA with SHA-256)

        if (jwk.containsKey("kid")) {
            // Pass through the key ID if it exists in the source JWK
            coseKey.put(2, ((String) jwk.get("kid")).getBytes(java.nio.charset.StandardCharsets.UTF_8));
        }


        // Map curve
        String crv = (String) jwk.get("crv");
        switch (crv) {
            case "P-256" -> coseKey.put(-1, 1);
            case "P-384" -> coseKey.put(-1, 2);
            case "P-521" -> coseKey.put(-1, 3);
            case null, default -> throw new IllegalArgumentException("Unsupported curve for EC2 key type: " + crv);
        }

        coseKey.put(-2, Base64.getUrlDecoder().decode((String) jwk.get("x")));
        if (jwk.containsKey("y")) {
            coseKey.put(-3, Base64.getUrlDecoder().decode((String) jwk.get("y")));
        }

        Map<String, Object> deviceKeyInfo = new HashMap<>();
        deviceKeyInfo.put("deviceKey", coseKey);
        return deviceKeyInfo;
    }

    /**
     * Signs the MSO using COSE_Sign1 structure via ProofGenerator
     */
    public byte[] signMSO(Map<String, Object> mso, String appID, String refID, String signAlgorithm) throws Exception {
        try {
            byte[] msoCbor = encodeToTaggedCBOR(mso);

            CoseSignRequestDto signRequest = new CoseSignRequestDto();

            String base64UrlPayload = Base64.getUrlEncoder().withoutPadding().encodeToString(msoCbor);

            signRequest.setPayload(base64UrlPayload);
            signRequest.setApplicationId(appID);
            signRequest.setReferenceId(refID);
            signRequest.setAlgorithm(signAlgorithm);
            signRequest.setIncludeCOSETag(false);

            // Set unprotected header in request
            signRequest.setUnprotectedHeader(Map.of("includeCertificate", true));

            String hexSignedData = coseSignatureService.coseSign1(signRequest).getSignedData();
            return hexStringToByteArray(hexSignedData);

        } catch (CertifyException e) {
            log.error("Error during COSE signing: {}", e.getMessage(), e);
            throw new CertifyException(ErrorConstants.VC_SIGNING_ERROR, "COSE signing failed: " + e.getMessage());
        }
    }

    /**
     * Converts hex string to byte array
     */
    private static byte[] hexStringToByteArray(String hexStr) {
        int len = hexStr.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hexStr.charAt(i), 16) << 4) + Character.digit(hexStr.charAt(i + 1), 16));
        }
        return data;
    }

    /**
     * ISO/IEC 18013-5, 9.3.1: validityInfo.signed must fall within the validity of the certificate in
     * the MSO header. signed is set from the certificate read before signing, so if the key is rotated
     * in between, x5chain can carry a certificate that starts after signed; such an mDL is refused
     * rather than issued.
     */
    public static void requireSignedWithinCertificate(Map<String, Object> mso, byte[] signedMSO) throws Exception {
        Object signedValue = untagDate(((Map<?, ?>) mso.get(Constants.VALIDITY_INFO)).get(Constants.SIGNED));
        Instant signed = Instant.parse((String) signedValue);
        X509Certificate certificate = x5chainLeaf(signedMSO);
        if (signed.isBefore(certificate.getNotBefore().toInstant())
                || signed.isAfter(certificate.getNotAfter().toInstant())) {
            throw new IllegalStateException("validityInfo.signed " + signedValue
                    + " is outside the validity of the certificate in the MSO header");
        }
    }

    /** The leaf certificate of the x5chain (label 33) in the unprotected header of a COSE_Sign1. */
    private static X509Certificate x5chainLeaf(byte[] signedMSO) throws Exception {
        DataItem cose = new CborDecoder(new ByteArrayInputStream(signedMSO)).decode().get(0);
        DataItem unprotectedHeader = ((Array) cose).getDataItems().get(1);
        DataItem x5chain = ((co.nstant.in.cbor.model.Map) unprotectedHeader).get(new UnsignedInteger(33));
        if (x5chain instanceof Array chain) {
            x5chain = chain.getDataItems().get(0);
        }
        if (!(x5chain instanceof ByteString certificate)) {
            throw new IllegalStateException("The MSO header has no x5chain certificate");
        }
        return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(certificate.getBytes()));
    }

    /**
     * Creates the final IssuerSigned structure combining namespaces and issuerAuth
     */

    public static Map<String, Object> createIssuerSignedStructure(Map<String, Object> processedNamespaces, byte[] signedMSO) throws IOException {
        try {
            var di = new CborDecoder(new java.io.ByteArrayInputStream(signedMSO)).decode();
            if (di.isEmpty()) {
                throw new IOException("Failed to decode COSE_Sign1: empty result");
            }
            DataItem cose = di.get(0);
            Map<String, Object> out = new HashMap<>();
            out.put(Constants.NAMESPACES, processedNamespaces);
            out.put("issuerAuth", cose);
            return out;
        } catch (CborException e) {
            throw new IOException("Failed to decode COSE_Sign1", e);
        }
    }
}