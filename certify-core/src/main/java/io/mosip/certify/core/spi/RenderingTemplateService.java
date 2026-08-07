/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.core.spi;

import io.mosip.certify.core.dto.RenderingTemplateDTO;

import java.util.List;

public interface RenderingTemplateService {
    RenderingTemplateDTO getTemplate(String id);
    List<RenderingTemplateDTO> getAllTemplates(String credentialConfigKeyId);
}
