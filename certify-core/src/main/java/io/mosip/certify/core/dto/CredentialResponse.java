/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.core.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;
import java.util.List;

@Data
public class CredentialResponse<T> {

    /**
     * Contains issued Credentials for immediate issuance.
     * Each credential MAY be a JSON string or a JSON object, depending on the Credential format.
     */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private List<CredentialWrapper<T>> credentials;

    @Data
    public static class CredentialWrapper<T> {
        @JsonInclude(JsonInclude.Include.NON_NULL)
        private T credential;
    }
}