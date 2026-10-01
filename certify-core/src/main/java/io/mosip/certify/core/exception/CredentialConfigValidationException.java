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

import io.mosip.certify.core.dto.Error;

import java.util.Collections;
import java.util.List;

/**
 * Carries every validation failure found while validating a credential configuration
 * request, so an issuer can correct the whole payload in a single pass instead of
 * resubmitting once per error.
 */
public class CredentialConfigValidationException extends CertifyException {

    private final List<Error> errors;

    public CredentialConfigValidationException(List<Error> errors) {
        super(errors.getFirst().getErrorCode(), errors.getFirst().getErrorMessage());
        this.errors = Collections.unmodifiableList(errors);
    }

    public List<Error> getErrors() {
        return errors;
    }
}
