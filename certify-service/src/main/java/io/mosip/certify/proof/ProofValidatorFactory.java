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
package io.mosip.certify.proof;

import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.exception.CertifyException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class ProofValidatorFactory {

    @Autowired
    private List<ProofValidator> proofValidators;

    public ProofValidator getProofValidator(String proofType) {
       return proofValidators.stream()
                .filter(v -> v.getProofType().equals(proofType))
                .findFirst()
                .orElseThrow(
                        () -> new CertifyException(ErrorConstants.UNSUPPORTED_PROOF_TYPE, "The proof type " + proofType + " is not supported."));
    }
}
