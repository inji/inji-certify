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
package io.mosip.certify.services;

import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Component;

import io.mosip.certify.core.dto.RenderingTemplateDTO;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.exception.RenderingTemplateException;
import io.mosip.certify.core.spi.RenderingTemplateService;
import io.mosip.certify.entity.RenderingTemplate;
import io.mosip.certify.repository.RenderingTemplateRepository;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
public class RenderingTemplateServiceImpl implements RenderingTemplateService {
    @Autowired
    RenderingTemplateRepository renderTemplateRepository;

    @Override
    @Cacheable(cacheNames="renderTemplate", key="#id")
    public RenderingTemplateDTO getTemplate(String id) {
        Optional<RenderingTemplate> optional = renderTemplateRepository.findById(id);
        RenderingTemplate renderingTemplate = optional.orElseThrow(() -> new RenderingTemplateException(ErrorConstants.INVALID_TEMPLATE_ID));
        RenderingTemplateDTO renderingTemplateDTO = new RenderingTemplateDTO();
        renderingTemplateDTO.setId(renderingTemplate.getId());
        renderingTemplateDTO.setTemplate(renderingTemplate.getTemplate());
        renderingTemplateDTO.setCreatedTimes(renderingTemplate.getCreatedtimes());
        renderingTemplateDTO.setUpdatedTimes(renderingTemplate.getUpdatedtimes());

        return renderingTemplateDTO;
    }
}
