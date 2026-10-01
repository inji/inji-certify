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
package io.mosip.certify.plugin.impl;

import io.mosip.certify.api.dto.AuditDTO;
import org.slf4j.MDC;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;


import io.mosip.certify.api.spi.AuditPlugin;
import io.mosip.certify.api.util.Action;
import io.mosip.certify.api.util.ActionStatus;
import jakarta.validation.constraints.NotNull;
import lombok.extern.slf4j.Slf4j;

@ConditionalOnProperty(value = "mosip.certify.integration.audit-plugin", havingValue = "LoggerAuditService")
@Component
@Slf4j
public class LoggerAuditService implements AuditPlugin {

	@Async
    @Override
    public void logAudit(@NotNull Action action, @NotNull ActionStatus status, @NotNull AuditDTO auditDTO, Throwable t) {
        audit(null, action, status, auditDTO, t);
    }
    
    @Async
    @Override
	public void logAudit(String username, Action action, ActionStatus status, AuditDTO auditDTO, Throwable t) {
    	audit(username, action, status, auditDTO, t);
	}

    private void addAuditDetailsToMDC(AuditDTO auditDTO) {
        if(auditDTO != null) {
            MDC.put("transactionId", auditDTO.getTransactionId());
        }
    }
    
    public void audit(String username, Action action, ActionStatus status, AuditDTO auditDTO, Throwable t) {
    	addAuditDetailsToMDC(auditDTO);
        try {
            if(t != null) {
                log.error(action.name(), t);
                return;
            }

            switch (status) {
                case ERROR:
                    log.error(action.name());
                    break;
                default:
                    log.info(username != null ? "Sessionuser: " +username+ "with action: " +action.name() : action.name());
            }
        } finally {
            MDC.clear();
        }
    }
}
