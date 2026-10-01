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
package io.mosip.certify.api.spi;

import foundation.identity.jsonld.JsonLDObject;
import io.mosip.certify.api.dto.VCRequestDto;
import io.mosip.certify.api.dto.VCResult;
import io.mosip.certify.api.exception.VCIExchangeException;

import java.util.Map;
/**
 * VCIssuancePlugin is implemented by VC plugin
 *  implementors who want to make use of an existing VC Issuance Infrastructure
 *  or want to do everything by themselves to generate the VC from the plugin.
 *  VC is received by the plugin and sent to Certify and forwarded to the
 *  client applications.
 */
public interface VCIssuancePlugin {

    /**
     * Applicable for formats : ldp_vc
     * @param vcRequestDto
     * @param holderId Holders key material as either DID / KID. This should be used for cryptographic binding of the VC
     * @param identityDetails Parsed access-token or introspect endpoint response if token is opaque.
     * @return
     */
    VCResult<JsonLDObject> getVerifiableCredentialWithLinkedDataProof(VCRequestDto vcRequestDto, String holderId,
                                                                      Map<String, Object> identityDetails) throws VCIExchangeException;

    /**
     * Applicable for formats : jwt_vc_json, jwt_vc_json-ld, mso_doc
     * @param vcRequestDto
     * @param holderId
     * @param identityDetails
     * @return
     */
    VCResult<String> getVerifiableCredential(VCRequestDto vcRequestDto, String holderId,
                                                                             Map<String, Object> identityDetails) throws VCIExchangeException;
}
