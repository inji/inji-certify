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

/**
 * Raised for any failure to validate a DPoP proof (RFC 9449 §4.3).
 *
 * <p>Mirrors eSignet's exception of the same name. The message-carrying
 * constructor is the addition: eSignet's variant carries only the error code, so
 * every DPoP failure reaches the client as a bare {@code invalid_dpop_proof}.
 * Keeping a description here means a wallet developer is told which check failed
 * - the descriptions are written to be safe to return, naming the claim at fault
 * and never echoing key material or token contents.
 */
public class InvalidDpopHeaderException extends CertifyException {

    public InvalidDpopHeaderException() {
        super(ErrorConstants.INVALID_DPOP_PROOF);
    }

    public InvalidDpopHeaderException(String message) {
        super(ErrorConstants.INVALID_DPOP_PROOF, message);
    }
}
