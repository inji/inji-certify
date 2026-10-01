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

/**
 * Constants for Interactive Authorization Request (IAR) functionality
 */
public class IarConstants {

    // OAuth 2.0 Response Types
    public static final String RESPONSE_TYPE_CODE = "code";

    // OAuth 2.0 Grant Types
    public static final String GRANT_TYPE_AUTHORIZATION_CODE = "authorization_code";

    // PKCE Code Challenge Methods
    public static final String CODE_CHALLENGE_METHOD_S256 = "S256";

    // Authorization Detail Type
    public static final String AUTHORIZATION_DETAILS_TYPE = "openid_credential";

    // Content Types
    public static final String UNSUPPORTED_RESPONSE_TYPE = "unsupported_response_type";
    public static final String MISSING_INTERACTION_TYPE = "missing_interaction_type";
}
