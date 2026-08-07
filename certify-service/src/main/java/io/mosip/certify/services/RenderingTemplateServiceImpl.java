/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.services;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

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
        return toDTO(renderingTemplate);
    }

    @Override
    @Cacheable(cacheNames="renderTemplates", key="#credentialConfigKeyId")
    public List<RenderingTemplateDTO> getAllTemplates(String credentialConfigKeyId) {
        List<RenderingTemplate> templates = renderTemplateRepository.findByCredentialConfigKeyId(credentialConfigKeyId);
        return templates.stream().map(this::toDTO).collect(Collectors.toList());
    }

    private RenderingTemplateDTO toDTO(RenderingTemplate renderingTemplate) {
        RenderingTemplateDTO dto = new RenderingTemplateDTO();
        dto.setId(renderingTemplate.getId());
        dto.setTemplate(renderingTemplate.getTemplate());
        dto.setLanguage(renderingTemplate.getLanguage());
        dto.setSide(renderingTemplate.getSide());
        dto.setCreatedTimes(renderingTemplate.getCreatedtimes());
        dto.setUpdatedTimes(renderingTemplate.getUpdatedtimes());
        return dto;
    }
}
