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
package io.mosip.certify.api.dto;

import lombok.Data;

import java.util.List;
import java.util.Map;

@Data
public class VCRequestDto {
    private List<String> context; //holds @context values
    private List<String> type;
    private String format;
    private Map<String, Object> credentialSubject;
    private String doctype;
    private Map<String, Object> claims;
    private String vct; // SD-JWT VC Type
}
