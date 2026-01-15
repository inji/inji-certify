/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
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
