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
package io.mosip.certify.core.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

import java.util.List;

/**
 * Configuration structure for verifiable claims
 * Matches the format used in inji-verify's config.json
 */
@Data
public class VerifiableClaimsConfig {
    
    @JsonProperty("verifiableClaims")
    private List<VerifiableClaim> verifiableClaims;
    
    @Data
    public static class VerifiableClaim {
        private String logo;
        private String name;
        private String type;
        private Boolean essential;
        private ClaimDefinition definition;
    }
    
    @Data
    public static class ClaimDefinition {
        private String purpose;
        private Format format;
        
        @JsonProperty("input_descriptors")
        private List<InputDescriptor> inputDescriptors;
    }
    
    @Data
    public static class Format {
        @JsonProperty("ldp_vc")
        private LdpVc ldpVc;
    }
    
    @Data
    public static class LdpVc {
        @JsonProperty("proof_type")
        private List<String> proofType;
    }
    
    @Data
    public static class InputDescriptor {
        private String id;
        private Format format;
        private Constraints constraints;
    }
    
    @Data
    public static class Constraints {
        private List<FieldConstraint> fields;
    }
    
    @Data
    public static class FieldConstraint {
        private List<String> path;
        private Filter filter;
    }
    
    @Data
    public static class Filter {
        private String type;
        private String pattern;
    }
}
