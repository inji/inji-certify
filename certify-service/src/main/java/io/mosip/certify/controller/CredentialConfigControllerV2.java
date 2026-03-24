package io.mosip.certify.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import io.mosip.certify.core.dto.CredentialConfigResponse;
import io.mosip.certify.core.dto.CredentialConfigurationDTOV2;
import io.mosip.certify.core.spi.CredentialConfigurationService;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequestMapping("/v2/credential-configurations")
public class CredentialConfigControllerV2 {

    @Autowired
    private CredentialConfigurationService credentialConfigurationService;

    @PostMapping(produces = "application/json")
    public ResponseEntity<CredentialConfigResponse> addCredentialConfiguration(@Valid @RequestBody CredentialConfigurationDTOV2 credentialConfigurationRequest) throws JsonProcessingException {

        CredentialConfigResponse credentialConfigResponse = credentialConfigurationService.addCredentialConfigurationV2(credentialConfigurationRequest);
        return new ResponseEntity<>(credentialConfigResponse, HttpStatus.CREATED);
    }

    @GetMapping(value = "/{credentialConfigKeyId}", produces = "application/json")
    public ResponseEntity<CredentialConfigurationDTOV2> getCredentialConfigurationById(@PathVariable String credentialConfigKeyId) throws JsonProcessingException {

        CredentialConfigurationDTOV2 credentialConfigurationDTO = credentialConfigurationService.getCredentialConfigurationByIdV2(credentialConfigKeyId);
        return new ResponseEntity<>(credentialConfigurationDTO, HttpStatus.OK);
    }

    @PutMapping(value = "/{credentialConfigKeyId}", produces = "application/json")
    public ResponseEntity<CredentialConfigResponse> updateCredentialConfiguration(@PathVariable String credentialConfigKeyId,
                                                                                  @Valid @RequestBody CredentialConfigurationDTOV2 credentialConfigurationRequest) throws JsonProcessingException {

        CredentialConfigResponse credentialConfigResponse = credentialConfigurationService.updateCredentialConfigurationV2(credentialConfigKeyId, credentialConfigurationRequest);
        return new ResponseEntity<>(credentialConfigResponse, HttpStatus.OK);
    }

    @DeleteMapping(value = "/{credentialConfigKeyId}", produces = "application/json")
    public ResponseEntity<String> deleteCredentialConfigurationById(@PathVariable String credentialConfigKeyId) {

        String response = credentialConfigurationService.deleteCredentialConfigurationById(credentialConfigKeyId);
        return new ResponseEntity<>("Deleted configuration with id: " + response, HttpStatus.OK);
    }
}
