/*
 * Copyright 2024 Modular Open Source Identity Platform
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.mosip.certify.controller;

import io.mosip.certify.core.dto.CredentialStatusResponse;
import io.mosip.certify.core.dto.UpdateCredentialStatusRequest;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.spi.CredentialStatusService;
import io.mosip.certify.services.StatusListCredentialService;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequestMapping("/credentials")
public class CredentialStatusController {

    @Autowired
    private StatusListCredentialService statusListCredentialService;

    @Autowired
    private CredentialStatusService credentialStatusService;

    /**
     * Get Status List Credential by ID with optional fragment support
     * Handles URLs like: /{id} or /{id}#{fragment}
     *
     * @param id The status list credential ID
    //     * @param fragment Optional fragment identifier (for specific index references)
     * @return Status List VC JSON document
     * @throws CertifyException
     */
    @GetMapping(value = "/status-list/{id}", produces = "application/json")
    public String getStatusListById(@PathVariable("id") String id) throws CertifyException {

        log.debug("Retrieving status list credential with ID: {}", id);
        return statusListCredentialService.getStatusListCredential(id);
    }

    @PostMapping(value = "/status", produces = "application/json")
    public ResponseEntity<CredentialStatusResponse> updateCredential(
            @Valid @RequestBody UpdateCredentialStatusRequest updateCredentialStatusRequest) {
        CredentialStatusResponse result = credentialStatusService.updateCredentialStatus(updateCredentialStatusRequest);
        if (result == null) {
            return ResponseEntity.noContent().build();
        }
        return ResponseEntity.ok(result);
    }
}