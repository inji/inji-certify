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
package io.mosip.certify.api.exception;

import io.mosip.certify.api.util.ErrorConstants;

public class VCIExchangeException extends Exception {
    private String errorCode;

    public VCIExchangeException() {
        super(ErrorConstants.VCI_EXCHANGE_FAILED);
        this.errorCode = ErrorConstants.VCI_EXCHANGE_FAILED;
    }

    public VCIExchangeException(String errorCode) {
        super(errorCode);
        this.errorCode = errorCode;
    }

    public VCIExchangeException(String errorCode, String errorMessage) {
        super(errorCode +  " -> " +  errorMessage);
        this.errorCode = errorCode;
    }

    public String getErrorCode() {
        return errorCode;
    }
}
