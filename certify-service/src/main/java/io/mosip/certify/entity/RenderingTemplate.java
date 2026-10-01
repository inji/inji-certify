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
package io.mosip.certify.entity;

import io.mosip.certify.core.constants.ErrorConstants;
import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@Entity
@AllArgsConstructor
@NoArgsConstructor
@Table(name = "rendering_template")
public class RenderingTemplate {
    @Id
    private String id;

    @NotBlank(message = ErrorConstants.EMPTY_TEMPLATE_CONTENT)
    @Column(name = "template")
    private String template;

    @Column(name = "cr_dtimes")
    private LocalDateTime createdtimes;

    @Column(name = "upd_dtimes")
    private LocalDateTime updatedtimes;
}
