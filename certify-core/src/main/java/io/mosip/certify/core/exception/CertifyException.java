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
package io.mosip.certify.core.exception;

import io.mosip.certify.core.constants.ErrorConstants;

public class CertifyException extends RuntimeException {

    private String errorCode;
    // TODO: should we add an optional errorDescription
    //  field to simplify debugging as per spec
    //  https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-ID1.html#section-7.3.1.2-3.2

    public CertifyException() {
        super(ErrorConstants.UNKNOWN_ERROR);
        this.errorCode = ErrorConstants.UNKNOWN_ERROR;
    }

    public CertifyException(String errorCode) {
        super(errorCode);
        this.errorCode = errorCode;
    }

    public CertifyException(String errorCode, String message, Throwable cause) {
        super(message, cause);
        this.errorCode = errorCode;
    }

    public CertifyException(String errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
    }

    public String getErrorCode() {
        return errorCode;
    }
}
