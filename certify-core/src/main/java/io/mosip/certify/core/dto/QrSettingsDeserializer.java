package io.mosip.certify.core.dto;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.exception.CertifyException;

import java.io.IOException;
import java.util.*;

/**
 * Custom deserializer for qrSettings that rejects duplicate keys within
 * each individual map block
 */
public class QrSettingsDeserializer extends JsonDeserializer<List<Map<String, Object>>> {

    @Override
    public List<Map<String, Object>> deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
        if (p.currentToken() == JsonToken.VALUE_NULL) {
            return null;
        }
        if (p.currentToken() != JsonToken.START_ARRAY) {
            throw new CertifyException(ErrorConstants.INVALID_REQUEST, "qrSettings must be an array of objects.");
        }

        List<Map<String, Object>> result = new ArrayList<>();

        while (p.nextToken() != JsonToken.END_ARRAY) {
            if (p.currentToken() != JsonToken.START_OBJECT) {
                throw new CertifyException(ErrorConstants.INVALID_REQUEST, "Each qrSettings entry must be an object.");
            }
            result.add(deserializeMapWithDuplicateCheck(p, ctxt));
        }

        return result;
    }

    private Map<String, Object> deserializeMapWithDuplicateCheck(JsonParser p, DeserializationContext ctxt) throws IOException {
        Map<String, Object> map = new LinkedHashMap<>();
        Set<String> seenKeys = new HashSet<>();

        while (p.nextToken() != JsonToken.END_OBJECT) {
            String fieldName = p.currentName();

            if (!seenKeys.add(fieldName)) {
                throw new CertifyException(ErrorConstants.QR_DUPLICATE_LABELS,
                        "Duplicate fields detected inside qrSettings.");
            }

            JsonToken valueToken = p.nextToken();
            Object value;
            if (valueToken == JsonToken.START_OBJECT) {
                value = deserializeMapWithDuplicateCheck(p, ctxt);
            } else {
                value = p.readValueAs(Object.class);
            }
            map.put(fieldName, value);
        }

        return map;
    }
}
