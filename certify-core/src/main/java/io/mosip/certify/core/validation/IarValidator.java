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
package io.mosip.certify.core.validation;

import io.mosip.certify.core.dto.IarRequest;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import org.springframework.util.StringUtils;

public class IarValidator implements ConstraintValidator<ValidIar, IarRequest> {
	@Override
	public boolean isValid(IarRequest value, ConstraintValidatorContext context) {
		if (value == null) {
			context.disableDefaultConstraintViolation();
			context.buildConstraintViolationWithTemplate("IAR request is required")
				   .addConstraintViolation();
			return false;
		}

		boolean hasAuthSession = StringUtils.hasText(value.getAuth_session());
		boolean hasVp = StringUtils.hasText(value.getOpenid4vp_response());

		boolean hasInitial =
			StringUtils.hasText(value.getResponse_type()) &&
			StringUtils.hasText(value.getCode_challenge()) &&
			StringUtils.hasText(value.getCode_challenge_method());

		// Exactly one of the flows must be present
		boolean isPresentationFlow = hasAuthSession && hasVp;
		boolean isInitialFlow = hasInitial && !hasAuthSession && !hasVp;

		if (isPresentationFlow || isInitialFlow) {
			return true;
		}

		context.disableDefaultConstraintViolation();
		context.buildConstraintViolationWithTemplate(
			"Invalid IAR request: either provide auth_session and openid4vp_response, or the initial authorization parameters"
		).addConstraintViolation();
		return false;
	}
}