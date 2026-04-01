package io.mosip.certify.core.dto;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.deser.std.UntypedObjectDeserializer;
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
        if (p.currentToken() != JsonToken.START_ARRAY) {
            return null;
        }

        List<Map<String, Object>> result = new ArrayList<>();

        while (p.nextToken() != JsonToken.END_ARRAY) {
            if (p.currentToken() == JsonToken.START_OBJECT) {
                result.add(deserializeMapWithDuplicateCheck(p, ctxt));
            }
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

            p.nextToken();
            Object value = UntypedObjectDeserializer.Vanilla.std.deserialize(p, ctxt);
            map.put(fieldName, value);
        }

        return map;
    }
}
