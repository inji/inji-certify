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
import io.mosip.certify.core.constants.VCIErrorConstants;
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
import java.time.Clock;
import java.time.Instant;
import java.time.LocalDate;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.KeyType;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.Map;
import java.util.function.BiConsumer;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
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

    /** The CBOR tag of a full-date (RFC 8943). */
    public static final int FULL_DATE_TAG = 1004;

    /** The CBOR tag of a tdate, an RFC 3339 date-time (RFC 8949). */
    public static final int TDATE_TAG = 0;

    /** The leading bytes of a JPEG (SOI marker). */
    private static final byte[] JPEG_SIGNATURE = {(byte) 0xFF, (byte) 0xD8, (byte) 0xFF};

    /** The leading bytes of a JPEG2000 codestream (SOC and SIZ markers). */
    private static final byte[] JPEG2000_CODESTREAM_SIGNATURE = {(byte) 0xFF, 0x4F, (byte) 0xFF, 0x51};

    /** The leading bytes of a JP2 file (the JPEG2000 signature box). */
    private static final byte[] JP2_SIGNATURE = {0x00, 0x00, 0x00, 0x0C, 0x6A, 0x50, 0x20, 0x20};

    /** The range a CBOR integer (major types 0 and 1) holds: -2^64 to 2^64 - 1 (RFC 8949, 3.1). */
    private static final BigInteger CBOR_INTEGER_MIN = BigInteger.ONE.shiftLeft(64).negate();

    private static final BigInteger CBOR_INTEGER_MAX = BigInteger.ONE.shiftLeft(64).subtract(BigInteger.ONE);

    private static final String INVALID_PHOTO_ID_BIRTH_DATE =
            "birth_date must be a full-date (YYYY-MM-DD) or a map with a full-date birth_date and an optional approximate_mask";

    private final ObjectMapper objectMapper;

    private final MDocConfig mDocConfig;

    private final CoseSignatureService coseSignatureService;

    private final KeymanagerService keymanagerService;

    /** The time the validityInfo dates are taken from. */
    private final Clock clock;

    @Autowired
    public MDocProcessor(ObjectMapper objectMapper,
                         MDocConfig mDocConfig,
                         CoseSignatureService coseSignatureService,
                         KeymanagerService keymanagerService) {
        this(objectMapper, mDocConfig, coseSignatureService, keymanagerService, Clock.systemUTC());
    }

    /** With the clock the validityInfo dates are taken from, so that tests can fix the time. */
    MDocProcessor(ObjectMapper objectMapper,
                  MDocConfig mDocConfig,
                  CoseSignatureService coseSignatureService,
                  KeymanagerService keymanagerService,
                  Clock clock) {
        this.objectMapper = objectMapper;
        this.mDocConfig = mDocConfig;
        this.coseSignatureService = coseSignatureService;
        this.keymanagerService = keymanagerService;
        this.clock = clock;
    }

    /**
     * The notBefore of the certificate that signing with this key puts in the MSO header (x5chain):
     * keymanager signs with the key's current certificate, which getCertificate returns.
     */
    public ZonedDateTime signingCertificateNotBefore(String appID, String refID) throws CertificateException {
        // An mso_mdoc configuration names its key (keyManagerAppId / keyManagerRefId), so there is no default
        // key to fall back to; the key-alias-mapper allows an empty refId.
        String certificatePem = keymanagerService.getCertificate(appID, Optional.ofNullable(refID)).getCertificate();
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
                if (!nameSpacesNode.isObject()) {
                    throw new IllegalArgumentException("nameSpaces must be an object mapping each namespace to its elements");
                }
                nameSpacesNode.fieldNames().forEachRemaining(namespaceName -> {
                    JsonNode namespaceItems = nameSpacesNode.get(namespaceName);
                    List<Map<String, Object>> processedItems = processNamespaceItems(namespaceName, namespaceItems);
                    // ISO/IEC 18013-5 IssuerNameSpaces: a namespace holds at least one element, so one left
                    // without any is left out.
                    if (!processedItems.isEmpty()) {
                        nameSpaces.put(namespaceName, processedItems);
                    }
                });
            }
            finalMDoc.put(Constants.NAMESPACES, nameSpaces);
            requireValidElements(nameSpaces);

            // ISO/IEC 18013-5, 9.1.2.4: the timestamps "should" have a precision that limits
            // linkability, so they are the start of the UTC day of issuance rather than the exact
            // time. signed is not before the signing certificate's notBefore, though: it must fall
            // within the validity of the certificate in the MSO header (9.3.1), and on the day a
            // signing key is generated or rotated its certificate starts after 00:00:00Z. Every mDL
            // signed with that certificate on that day still gets the same value. validFrom is not
            // before signed or the mDL issue_date (7.2.1) and validUntil is validityPeriodYears
            // (at least 1) after validFrom, so signed <= validFrom < validUntil.
            ZonedDateTime signed = ZonedDateTime.now(clock.withZone(ZoneOffset.UTC)).truncatedTo(ChronoUnit.DAYS);
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

    /** An RFC 3339 date-time in UTC, preserving precision for boundary calculations, or null. */
    private static ZonedDateTime parseDateTime(String text) {
        try {
            if (!text.matches("\\d{4}-\\d{2}-\\d{2}[Tt]\\d{2}:\\d{2}:\\d{2}(?:\\.\\d+)?(?:[Zz]|[+-]\\d{2}:\\d{2})")) {
                return null;
            }
            return OffsetDateTime.parse(text, DateTimeFormatter.ISO_OFFSET_DATE_TIME)
                    .atZoneSameInstant(ZoneOffset.UTC);
        } catch (DateTimeParseException e) {
            return null;
        }
    }

    /** A validityInfo date written out in the template is refused: only its placeholder is accepted. */
    private static void requirePlaceholder(String name, String value, String placeholder) {
        if (!placeholder.equals(value)) {
            throw new IllegalArgumentException("validityInfo." + name + " must be " + placeholder
                    + "; Certify sets the validityInfo dates at issuance");
        }
    }

    /**
     * Process items within a namespace. Each must be an object with a text elementIdentifier and an
     * elementValue; a template without them fails naming the element by its namespace and position (and
     * identifier, when it has one), which is template text rather than a holder's data.
     */
    private List<Map<String, Object>> processNamespaceItems(String namespaceName, JsonNode namespaceItems) {
        String namespacePath = Constants.NAMESPACES + "." + namespaceName;
        if (!namespaceItems.isArray()) {
            throw new IllegalArgumentException(namespacePath + " must be an array of elements");
        }
        List<Map<String, Object>> processedItems = new ArrayList<>();
        // ISO/IEC 18013-5, 9.1.2.4: digestIDs are unique within a namespace and are drawn at random,
        // so the same element cannot be recognised by its ID across credentials. Any digestID in the
        // template is therefore ignored.
        Set<Integer> usedDigestIds = new HashSet<>();

        // First, add all items from template
        for (int index = 0; index < namespaceItems.size(); index++) {
            JsonNode item = namespaceItems.get(index);
            String elementPath = namespacePath + "[" + index + "]";
            if (!item.isObject()) {
                throw new IllegalArgumentException(elementPath + " must be an object with "
                        + Constants.ELEMENT_IDENTIFIER + " and " + Constants.ELEMENT_VALUE);
            }
            JsonNode identifier = item.get(Constants.ELEMENT_IDENTIFIER);
            if (identifier == null || !identifier.isTextual() || identifier.asText().isBlank()) {
                throw new IllegalArgumentException(elementPath + ": " + Constants.ELEMENT_IDENTIFIER + " is missing");
            }
            // An element whose value is null is unset, so it is left out rather than written as a CBOR null.
            // As for the mDL, a configuration's mandatory elements are checked on Add and Update, not here.
            JsonNode elementValue = item.get(Constants.ELEMENT_VALUE);
            if (elementValue == null) {
                throw new IllegalArgumentException(elementPath + " (" + identifier.asText() + "): "
                        + Constants.ELEMENT_VALUE + " is missing");
            }
            if (elementValue.isNull()) {
                continue;
            }
            Map<String, Object> itemMap = new HashMap<>();
            int digestId;
            do {
                digestId = SECURE_RANDOM.nextInt(Integer.MAX_VALUE);
            } while (!usedDigestIds.add(digestId));
            itemMap.put(Constants.DIGEST_ID, digestId);
            itemMap.put(Constants.ELEMENT_IDENTIFIER, identifier.asText());

            // Handle elementValue which could be string or complex object
            if (elementValue.isTextual()) {
                itemMap.put(Constants.ELEMENT_VALUE, elementValue.asText());
            } else {
                // Convert complex objects (like driving_privileges)
                Object value = objectMapper.convertValue(elementValue, Object.class);
                requireSupportedCborTags((String) itemMap.get(Constants.ELEMENT_IDENTIFIER), value);
                requireCborIntegers((String) itemMap.get(Constants.ELEMENT_IDENTIFIER), value);
                itemMap.put(Constants.ELEMENT_VALUE, value);
            }

            processedItems.add(itemMap);
        }

        return processedItems;
    }

    /**
     * A value the template tagged itself, {"__cbor_tag": tag, "__cbor_value": value}, in any namespace and at
     * any depth: the tag must be the integer 1004 with a full-date (YYYY-MM-DD) or 0 with an RFC 3339
     * date-time, the values the mDL date elements accept. The configuration check rejects any other tag,
     * but not a template it can't parse before rendering, nor the value a tag wraps. The message names the
     * element but not its value, so that a holder's data does not end up in the logs.
     */
    private static void requireSupportedCborTags(String identifier, Object value) {
        if (value instanceof Map<?, ?> map) {
            if (map.containsKey(Constants.__CBOR_TAG)) {
                Object tag = map.get(Constants.__CBOR_TAG);
                Object content = map.get(Constants.__CBOR_VALUE);
                if (Integer.valueOf(FULL_DATE_TAG).equals(tag)) {
                    if (!(content instanceof String text && isDateOnlyString(text))) {
                        throw new IllegalArgumentException(identifier + ": a value tagged 1004 must be a full-date (YYYY-MM-DD)");
                    }
                } else if (Integer.valueOf(TDATE_TAG).equals(tag)) {
                    if (!(content instanceof String text && parseDateTime(text) != null)) {
                        throw new IllegalArgumentException(identifier + ": a value tagged 0 must be an RFC 3339 date-time");
                    }
                } else {
                    throw new IllegalArgumentException(identifier + ": __cbor_tag must be the integer 0 (tdate) or 1004 (full-date)");
                }
                return;
            }
            map.values().forEach(child -> requireSupportedCborTags(identifier, child));
        } else if (value instanceof List<?> list) {
            list.forEach(child -> requireSupportedCborTags(identifier, child));
        }
    }

    /**
     * A JSON integer is encoded as a CBOR integer, which holds -2^64 to 2^64 - 1 (RFC 8949, 3.1). A larger one,
     * in any namespace and at any depth, is rejected rather than written as text. The message names the
     * element but not its value, so that a holder's data does not end up in the logs.
     */
    private static void requireCborIntegers(String identifier, Object value) {
        if (value instanceof BigInteger integer && !isCborInteger(integer)) {
            throw new IllegalArgumentException(identifier + ": an integer must be between -2^64 and 2^64 - 1");
        } else if (value instanceof Map<?, ?> map) {
            map.values().forEach(child -> requireCborIntegers(identifier, child));
        } else if (value instanceof List<?> list) {
            list.forEach(child -> requireCborIntegers(identifier, child));
        }
    }

    private static boolean isCborInteger(BigInteger integer) {
        return integer.compareTo(CBOR_INTEGER_MIN) >= 0 && integer.compareTo(CBOR_INTEGER_MAX) <= 0;
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
        if (!MDocConfig.SUPPORTED_DIGEST_ALGORITHMS.contains(digestAlgorithm)) {
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
                new CborEncoder(innerBaos).encode(convertToDataItem(preprocessForCBOR(encodeElement(namespaceName, element))));
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
     * The values of the namespaces whose encodings Certify knows are checked on the rendered template, before
     * anything is signed, so that invalid data fails as mdoc_template_processing_failed rather than as a
     * signing failure. calculateDigests then only tags and decodes them: a byte string can't cross the JSON
     * hand-off to addProof, so it is decoded there.
     */
    private static void requireValidElements(Map<String, Object> nameSpaces) {
        requireValidNamespaceElements(nameSpaces, MdlDataElements.NAMESPACE, MDocProcessor::requireValidMdlElement);
        requireValidNamespaceElements(nameSpaces, PhotoIdDataElements.NAMESPACE, MDocProcessor::requireValidPhotoIdElement);
    }

    private static void requireValidNamespaceElements(Map<String, Object> nameSpaces, String namespace,
                                                      BiConsumer<String, Object> requireValidElement) {
        if (!(nameSpaces.get(namespace) instanceof List<?> elements)) {
            return;
        }
        for (Object element : elements) {
            Map<?, ?> item = (Map<?, ?>) element;
            requireValidElement.accept((String) item.get(Constants.ELEMENT_IDENTIFIER), item.get(Constants.ELEMENT_VALUE));
        }
    }

    /**
     * ISO/IEC 18013-5, 7.2 (Table 5): a full-date element must be a date (YYYY-MM-DD), or for issue_date and
     * expiry_date a date-time, as text or already tagged (1004, 0) by the template; a byte-string element
     * must be base64 text, and portrait a JPEG or JPEG2000 image (7.2.2); driving_privileges must be an array
     * of DrivingPrivilege entries (7.2.4).
     */
    private static void requireValidMdlElement(String identifier, Object value) {
        if (MdlDataElements.FULL_DATE_OR_TDATE.contains(identifier)) {
            if (tdate(value) == null) {
                requireFullDate(value);
            }
        } else if (MdlDataElements.FULL_DATE.contains(identifier)) {
            requireFullDate(value);
        } else if (MdlDataElements.isByteString(identifier)) {
            requireByteString(identifier, value, MdlDataElements.PORTRAIT.equals(identifier));
        } else if (MdlDataElements.DRIVING_PRIVILEGES.equals(identifier)) {
            if (!(value instanceof List<?> privileges)) {
                throw new IllegalArgumentException("driving_privileges must be an array");
            }
            for (Object privilege : privileges) {
                if (!(privilege instanceof Map<?, ?> fields)
                        || !(fields.get(MdlDataElements.VEHICLE_CATEGORY_CODE) instanceof String code)
                        || code.isBlank()) {
                    throw new IllegalArgumentException("Invalid driving_privileges entry");
                }
                requireDrivingPrivilegeStructure(fields);
                for (String dateField : MdlDataElements.DRIVING_PRIVILEGE_FULL_DATE) {
                    if (fields.containsKey(dateField)) {
                        requireFullDate(fields.get(dateField));
                    }
                }
            }
        }
    }

    /**
     * ISO/IEC TS 23220-4, Annex C: birth_date is a full-date or a birth_date map, issue_date and expiry_date
     * are full-dates only and portrait_capture_date a date-time, as text or already tagged (1004, 0) by the
     * template; every age_over_NN is a boolean; portrait is a byte string, which
     * Certify requires to be a JPEG or JPEG2000 image. The messages leave the value out so that a holder's
     * data does not end up in the logs.
     */
    private static void requireValidPhotoIdElement(String identifier, Object value) {
        if (PhotoIdDataElements.BIRTH_DATE.equals(identifier)) {
            requirePhotoIdBirthDate(value);
        } else if (PhotoIdDataElements.FULL_DATE.contains(identifier)) {
            if (!isFullDate(value)) {
                throw new IllegalArgumentException(identifier + " must be a full-date (YYYY-MM-DD)");
            }
        } else if (PhotoIdDataElements.TDATE.contains(identifier)) {
            if (tdate(value) == null) {
                throw new IllegalArgumentException(identifier + " must be an RFC 3339 date-time");
            }
        } else if (PhotoIdDataElements.isByteString(identifier)) {
            requireByteString(identifier, value, PhotoIdDataElements.PORTRAIT.equals(identifier));
        } else if (PhotoIdDataElements.isAgeOver(identifier) && !(value instanceof Boolean)) {
            // A quoted "true" is text, which a verifier reading the attestation would not accept as one.
            throw new IllegalArgumentException(identifier + " must be a boolean (true or false), not text or a number");
        }
    }

    /**
     * ISO/IEC TS 23220-2, 6.3.1.1.3: birth_date is a full-date, or a map with a full-date birth_date and an
     * optional approximate_mask of eight digits, each 0 or 1, and no other keys. A value the template tagged
     * itself counts as the full-date form.
     */
    private static void requirePhotoIdBirthDate(Object value) {
        if (!(value instanceof Map<?, ?> map) || map.containsKey(Constants.__CBOR_TAG)) {
            if (!isFullDate(value)) {
                throw new IllegalArgumentException(INVALID_PHOTO_ID_BIRTH_DATE);
            }
            return;
        }
        if (!PhotoIdDataElements.BIRTH_DATE_KEYS.containsAll(map.keySet()) || !isFullDate(map.get(PhotoIdDataElements.BIRTH_DATE))) {
            throw new IllegalArgumentException(INVALID_PHOTO_ID_BIRTH_DATE);
        }
        if (map.containsKey(PhotoIdDataElements.APPROXIMATE_MASK)
                && !(map.get(PhotoIdDataElements.APPROXIMATE_MASK) instanceof String mask && mask.matches("[01]{8}"))) {
            throw new IllegalArgumentException("birth_date: approximate_mask must be 8 digits, each 0 or 1");
        }
    }

    /** A checked birth_date: the full-date, alone or inside the map, becomes tag 1004. */
    private static Object asPhotoIdBirthDate(Object value) {
        if (value instanceof Map<?, ?> map && !map.containsKey(Constants.__CBOR_TAG)) {
            Map<Object, Object> encoded = new HashMap<>(map);
            encoded.put(PhotoIdDataElements.BIRTH_DATE, asFullDate(map.get(PhotoIdDataElements.BIRTH_DATE)));
            return encoded;
        }
        return asFullDate(value);
    }

    /**
     * Values come from the templated JSON, so a byte string can only arrive as base64 text. An image must
     * be a JPEG or JPEG2000 image.
     */
    private static void requireByteString(String identifier, Object value, boolean image) {
        if (!(value instanceof String text)) {
            throw new IllegalArgumentException(identifier + " must be base64 encoded");
        }
        byte[] bytes = decodeBase64(identifier, text);
        if (image && !isJpegOrJpeg2000(bytes)) {
            throw new IllegalArgumentException(identifier + " must be a JPEG or JPEG2000 image");
        }
    }

    /**
     * Applies the encodings of the namespaces Certify knows to an element whose value processTemplatedJson
     * has checked. Elements of any other namespace are left as they are; a template tags them explicitly if
     * it needs to.
     */
    private static Map<String, Object> encodeElement(String namespace, Map<String, Object> element) {
        if (MdlDataElements.NAMESPACE.equals(namespace)) {
            return encodeMdlElement(element);
        }
        if (PhotoIdDataElements.NAMESPACE.equals(namespace)) {
            return encodePhotoIdElement(element);
        }
        return element;
    }

    /**
     * ISO/IEC TS 23220-4, Annex C: a date of a full-date element, and the birth date alone or inside its
     * birth_date map, becomes tag 1004, a date-time of a tdate
     * element a tdate (tag 0) in UTC without fractions of seconds, and portrait is decoded from the base64
     * text the template carries.
     */
    private static Map<String, Object> encodePhotoIdElement(Map<String, Object> element) {
        String identifier = (String) element.get(Constants.ELEMENT_IDENTIFIER);
        Object value = element.get(Constants.ELEMENT_VALUE);
        Object encoded = value;
        if (PhotoIdDataElements.BIRTH_DATE.equals(identifier)) {
            encoded = asPhotoIdBirthDate(value);
        } else if (PhotoIdDataElements.FULL_DATE.contains(identifier)) {
            encoded = asFullDate(value);
        } else if (PhotoIdDataElements.TDATE.contains(identifier)) {
            encoded = createCBORTaggedDateTime(tdate(value).format(VALIDITY_INFO_DATETIME_FORMATTER));
        } else if (PhotoIdDataElements.isByteString(identifier)) {
            encoded = decodeBase64(identifier, (String) value);
        }
        return withEncodedValue(element, value, encoded);
    }

    /** The element itself when its value is unchanged, otherwise a copy holding the encoded value. */
    private static Map<String, Object> withEncodedValue(Map<String, Object> element, Object value, Object encoded) {
        if (encoded == value) {
            return element;
        }
        Map<String, Object> encodedElement = new HashMap<>(element);
        encodedElement.put(Constants.ELEMENT_VALUE, encoded);
        return encodedElement;
    }

    /**
     * Applies the Table 5 encodings to an element of the mDL namespace: a date-only value of a full-date
     * element, including the dates inside each driving privilege, becomes tag 1004, a date-time of
     * issue_date or expiry_date a tdate (tag 0), and a byte-string element is decoded from the base64 text
     * the template carries.
     */
    private static Map<String, Object> encodeMdlElement(Map<String, Object> element) {
        String identifier = (String) element.get(Constants.ELEMENT_IDENTIFIER);
        Object value = element.get(Constants.ELEMENT_VALUE);
        Object encoded = value;
        if (MdlDataElements.FULL_DATE_OR_TDATE.contains(identifier)) {
            encoded = asFullDateOrTdate(value);
        } else if (MdlDataElements.FULL_DATE.contains(identifier)) {
            encoded = asFullDate(value);
        } else if (MdlDataElements.isByteString(identifier)) {
            encoded = decodeBase64(identifier, (String) value);
        } else if (MdlDataElements.DRIVING_PRIVILEGES.equals(identifier)) {
            List<Object> encodedPrivileges = new ArrayList<>();
            for (Object privilege : (List<?>) value) {
                Map<Object, Object> encodedFields = new HashMap<>((Map<?, ?>) privilege);
                for (String dateField : MdlDataElements.DRIVING_PRIVILEGE_FULL_DATE) {
                    if (encodedFields.containsKey(dateField)) {
                        encodedFields.put(dateField, asFullDate(encodedFields.get(dateField)));
                    }
                }
                encodedPrivileges.add(encodedFields);
            }
            encoded = encodedPrivileges;
        }
        return withEncodedValue(element, value, encoded);
    }

    /**
     * ISO/IEC 18013-5, 7.2.4: a DrivingPrivilege has no keys other than vehicle_category_code,
     * issue_date, expiry_date and codes. vehicle_category_code and the dates are checked by the caller.
     */
    private static void requireDrivingPrivilegeStructure(Map<?, ?> fields) {
        if (!MdlDataElements.DRIVING_PRIVILEGE_KEYS.containsAll(fields.keySet())) {
            throw new IllegalArgumentException("Invalid driving_privileges entry");
        }
        if (fields.containsKey(MdlDataElements.CODES)) {
            requireDrivingPrivilegeCodes(fields.get(MdlDataElements.CODES));
        }
    }

    /**
     * ISO/IEC 18013-5, 7.2.4: codes is a non-empty array of Code maps, each with a text code and,
     * optionally, a text sign and value, and no other keys.
     */
    private static void requireDrivingPrivilegeCodes(Object codes) {
        if (!(codes instanceof List<?> entries) || entries.isEmpty()) {
            throw new IllegalArgumentException("Invalid driving_privileges entry");
        }
        for (Object entry : entries) {
            if (!(entry instanceof Map<?, ?> code)
                    || !MdlDataElements.DRIVING_PRIVILEGE_CODE_KEYS.containsAll(code.keySet())
                    || !(code.get(MdlDataElements.CODE) instanceof String text) || text.isBlank()
                    || !isAbsentOrText(code, MdlDataElements.CODE_SIGN) || !isAbsentOrText(code, MdlDataElements.CODE_VALUE)) {
                throw new IllegalArgumentException("Invalid driving_privileges entry");
            }
        }
    }

    private static boolean isAbsentOrText(Map<?, ?> map, String key) {
        return !map.containsKey(key) || map.get(key) instanceof String;
    }

    /**
     * A Table 5 full-date: a date (YYYY-MM-DD) as text, or one the template already tagged 1004. Any
     * other value, type or tag is rejected. The message leaves the value out so that a holder's data
     * does not end up in the logs.
     */
    private static void requireFullDate(Object value) {
        if (!isFullDate(value)) {
            throw new IllegalArgumentException("Invalid mDL full-date");
        }
    }

    /** Whether the value is a date (YYYY-MM-DD) as text, or one the template already tagged 1004. */
    private static boolean isFullDate(Object value) {
        Object date = value instanceof String ? value : tagContent(value, FULL_DATE_TAG);
        return date instanceof String text && isDateOnlyString(text);
    }

    /** A checked full-date: text becomes tag 1004, and one the template already tagged is kept. */
    private static Object asFullDate(Object value) {
        return value instanceof String text ? createCBORTaggedDate(text) : value;
    }

    /** The content of a value the template tagged with this CBOR tag, or null. */
    private static Object tagContent(Object value, int tag) {
        if (value instanceof Map<?, ?> tagged && Integer.valueOf(tag).equals(tagged.get(Constants.__CBOR_TAG))) {
            return tagged.get(Constants.__CBOR_VALUE);
        }
        return null;
    }

    /** A date-time, as text or already tagged 0 by the template, in UTC; null when the value is not one. */
    private static ZonedDateTime tdate(Object value) {
        Object dateTimeText = value instanceof String ? value : tagContent(value, TDATE_TAG);
        if (dateTimeText instanceof String text && !isDateOnlyString(text)) {
            return parseDateTime(text);
        }
        return null;
    }

    /**
     * Table 5: issue_date and expiry_date are a full-date or a tdate. A checked date-time becomes a tdate
     * (tag 0) in UTC without fractions of seconds; anything else is a full-date.
     */
    private static Object asFullDateOrTdate(Object value) {
        ZonedDateTime dateTime = tdate(value);
        if (dateTime != null) {
            return createCBORTaggedDateTime(dateTime.format(VALIDITY_INFO_DATETIME_FORMATTER));
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

    /**
     * The portrait must be JPEG or JPEG2000 (ISO/IEC 18013-5, 7.2.2), recognised by its leading bytes:
     * a JPEG, a JPEG2000 codestream or a JP2 file.
     */
    private static boolean isJpegOrJpeg2000(byte[] image) {
        return startsWith(image, JPEG_SIGNATURE)
                || startsWith(image, JPEG2000_CODESTREAM_SIGNATURE)
                || startsWith(image, JP2_SIGNATURE);
    }

    private static boolean startsWith(byte[] bytes, byte[] prefix) {
        return bytes.length >= prefix.length
                && Arrays.equals(bytes, 0, prefix.length, prefix, 0, prefix.length);
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
        if (obj instanceof Integer || obj instanceof Long || obj instanceof Short || obj instanceof Byte) {
            long value = ((java.lang.Number) obj).longValue();
            if (value < 0) {
                return new NegativeInteger(value);
            } else {
                return new UnsignedInteger(value);
            }
        }
        // A JSON integer beyond the range of a long; processTemplatedJson has checked it fits a CBOR integer.
        if (obj instanceof BigInteger integer) {
            if (!isCborInteger(integer)) {
                throw new IllegalArgumentException("An integer must be between -2^64 and 2^64 - 1");
            }
            return integer.signum() < 0 ? new NegativeInteger(integer) : new UnsignedInteger(integer);
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
        // Any other number, such as a BigDecimal, has no exact CBOR encoding here, so it is rejected rather
        // than written as text.
        if (obj instanceof java.lang.Number) {
            throw new IllegalArgumentException("Unsupported number type: " + obj.getClass().getSimpleName());
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
     * Creates the Mobile Security Object (MSO) structure. digestAlgorithm must be the algorithm the
     * namespaceDigests were calculated with, so that the MSO declares the one its digests use.
     */
    public Map<String, Object> createMobileSecurityObject
    (Map<String, Object> mDocJson, Map<String, Map<Integer, byte[]>> namespaceDigests,
     String digestAlgorithm) throws Exception {

        Map<String, Object> mso = new HashMap<>();
        mso.put("version", mDocConfig.getMsoVersion());
        mso.put("digestAlgorithm", digestAlgorithm);

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
     * Creates the MSO's deviceKeyInfo from the holder's key.
     */
    private static Map<String, Object> createDeviceKeyInfo(Object deviceInfo) {
        Map<String, Object> deviceKeyInfo = new HashMap<>();
        deviceKeyInfo.put("deviceKey", toDeviceKey(deviceInfo));
        return deviceKeyInfo;
    }

    /**
     * Checks that the holder's key can be an mDL device key, without building the MSO, so that a
     * request can refuse every unusable holder key before it signs or stores anything.
     *
     * @throws CertifyException invalid_proof when the key can't be a device key
     */
    public static void requireValidDeviceKey(Object holderId) {
        toDeviceKey(holderId);
    }

    /** The holder's key as a COSE_Key device key, or invalid_proof when it can't be one. */
    private static Map<Object, Object> toDeviceKey(Object holderId) {
        if (holderId == null) {
            throw new IllegalArgumentException("Device info (holder ID) is required for mDoc credential");
        }
        String deviceKeyEncoded = holderId.toString();
        // The device key is written from the holder's JWK, so only a jwk header or a did:jwk can carry
        // it. Any other DID (did:key and the rest) is refused before decoding.
        if (deviceKeyEncoded.startsWith("did:") && !deviceKeyEncoded.startsWith(Constants.DID_JWK_PREFIX)) {
            String didMethod = "did:" + deviceKeyEncoded.split(":", 3)[1];
            throw new CertifyException(VCIErrorConstants.INVALID_PROOF,
                    "The holder key can't be an mDL device key: it must be sent as a JWK (jwk header or did:jwk), not as a "
                            + didMethod + ".");
        }
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

        Map<String, Object> jwk;
        try {
            String decodedJson = new String(Base64.getUrlDecoder().decode(deviceKeyEncoded), StandardCharsets.UTF_8);
            jwk = new ObjectMapper().readValue(decodedJson, Map.class);
        } catch (IllegalArgumentException | com.fasterxml.jackson.core.JsonProcessingException e) {
            throw new CertifyException(VCIErrorConstants.INVALID_PROOF,
                    "The holder key isn't a valid JWK, so it can't be an mDL device key.", e);
        }

        // ISO/IEC 18013-5, 9.1.5.2 (NOTE 2): the device key carries only the key itself, so alg
        // and kid are left out. A device key shall use a Table 22 curve (9.1.3.4); Certify supports
        // P-256 device keys only (EC2, crv 1), the curve Inji Wallet presents with. Each coordinate
        // must be 32 bytes (RFC 9053, 7.1.1), as a JWK's must (RFC 7518, 6.2.1.2), so a coordinate
        // missing its leading zeros is refused.
        String kty = jwk.get("kty") instanceof String k ? k : null;
        String crv = jwk.get("crv") instanceof String c ? c : null;
        if (!KeyType.EC.getValue().equals(kty) || !Curve.P_256.getName().equals(crv)) {
            throw unsupportedDeviceKey(kty, crv);
        }
        Map<Object, Object> coseKey = new HashMap<>();
        coseKey.put(1, 2);  // kty: EC2
        coseKey.put(-1, 1); // crv: P-256
        coseKey.put(-2, decodeCoordinate(jwk, "x", 32));
        coseKey.put(-3, decodeCoordinate(jwk, "y", 32));
        return coseKey;
    }

    /** The holder's key can't be an mDL device key: the proof is refused with invalid_proof. */
    private static CertifyException unsupportedDeviceKey(String kty, String crv) {
        return new CertifyException(VCIErrorConstants.INVALID_PROOF,
                "The holder key (kty " + kty + (crv == null ? "" : ", crv " + crv) + ") can't be an mDL device key: "
                        + "it must be an EC key on P-256 (ISO/IEC 18013-5, 9.1.3.4).");
    }

    private static byte[] decodeCoordinate(Map<String, Object> jwk, String name, int expectedLength) {
        if (!(jwk.get(name) instanceof String value)) {
            throw new CertifyException(VCIErrorConstants.INVALID_PROOF,
                    "The holder key has no '" + name + "' member, so it can't be an mDL device key.");
        }
        byte[] coordinate;
        try {
            coordinate = Base64.getUrlDecoder().decode(value);
        } catch (IllegalArgumentException e) {
            throw new CertifyException(VCIErrorConstants.INVALID_PROOF,
                    "The holder key has an invalid '" + name + "' member, so it can't be an mDL device key.", e);
        }
        if (coordinate.length != expectedLength) {
            throw new CertifyException(VCIErrorConstants.INVALID_PROOF,
                    "The holder key's '" + name + "' member has " + coordinate.length + " bytes instead of "
                            + expectedLength + " for crv " + jwk.get("crv") + ", so it can't be an mDL device key.");
        }
        return coordinate;
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