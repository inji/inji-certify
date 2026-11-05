package io.mosip.certify.controller;

import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.dto.CredentialIssuerMetadataDTO;
import io.mosip.certify.core.dto.Error;
import io.mosip.certify.core.dto.ResponseWrapper;
import io.mosip.certify.core.spi.CredentialConfigurationService;
import io.mosip.certify.core.spi.JwksService;
import io.mosip.certify.core.spi.VCIssuanceService;
import io.mosip.certify.core.util.CommonUtil;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Serves the .well-known documents: credential issuer metadata, DID document and JWKS.
 * <p>
 * Do not add {@code produces = "application/json"} to these mappings, as the other controllers have.
 * Certify does not sign its metadata, so every Accept value, application/jwt included, must get the
 * JSON document (OID4VCI 1.0 section 12.2.2). 
 */
@RestController
public class WellKnownController {

    private final CredentialConfigurationService credentialConfigurationService;

    private final VCIssuanceService vcIssuanceService;

    private final JwksService jwksService;

    public WellKnownController(CredentialConfigurationService credentialConfigurationService,
                               VCIssuanceService vcIssuanceService,
                               JwksService jwksService) {
        this.credentialConfigurationService = credentialConfigurationService;
        this.vcIssuanceService = vcIssuanceService;
        this.jwksService = jwksService;
    }

    @GetMapping("/.well-known/openid-credential-issuer")
    public ResponseEntity<CredentialIssuerMetadataDTO> getCredentialIssuerMetadata() {
        return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_JSON)
                .body(credentialConfigurationService.fetchCredentialIssuerMetadata());
    }

    @GetMapping("/.well-known/did.json")
    public ResponseEntity<Object> getDIDDocument() {
        Map<String, Object> didDocument = vcIssuanceService.getDIDDocument();
        if (didDocument == null) {
            // Built here, not thrown: the advice reports errors as 200, and a .well-known
            // result must not answer success with no document
            ResponseWrapper notFound = new ResponseWrapper<>();
            notFound.setResponseTime(CommonUtil.getUTCDateTime());
            notFound.setErrors(List.of(new Error(ErrorConstants.DID_DOCUMENT_NOT_FOUND, ErrorConstants.DID_DOCUMENT_NOT_FOUND)));
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(notFound);
        }
        return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_JSON)
                .body(didDocument);
    }

    @GetMapping("/.well-known/jwks.json")
    public ResponseEntity<Map<String, Object>> getJwks() {
        try {
            Map<String, Object> response = jwksService.getJwks();

            if (response != null && response.containsKey("keys")) {
                @SuppressWarnings("unchecked")
                List<Map<String, Object>> jwkList = (List<Map<String, Object>>) response.get("keys");
                return ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON).body(response);
            } else {
                Map<String, Object> errorResponse = new HashMap<>();
                errorResponse.put("keys", Collections.emptyList());
                return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).contentType(MediaType.APPLICATION_JSON).body(errorResponse);
            }

        } catch (Exception e) {
            // Return empty keys array per OAuth 2.0 spec - clients should handle this gracefully
            // Do NOT cache error responses - allow retries
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("keys", Collections.emptyList());
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).contentType(MediaType.APPLICATION_JSON).body(errorResponse);
        }
    }
}