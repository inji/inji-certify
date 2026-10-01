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
package io.mosip.certify.core.constants;

// Error constants specific to the OpenId4VCI Credential Error Response implementation
// Ref : https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-ID1.html#name-credential-error-response
public class VCIErrorConstants {
    public static final String INVALID_REQUEST = "invalid_request";
    public static final String INVALID_SCOPE = "invalid_scope";
    public static final String INVALID_CREDENTIAL_REQUEST = "invalid_credential_request";
    public static final String UNSUPPORTED_CREDENTIAL_TYPE = "unsupported_credential_type";
    public static final String UNSUPPORTED_CREDENTIAL_FORMAT = "unsupported_credential_format";
    public static final String INVALID_PROOF = "invalid_proof";
}
