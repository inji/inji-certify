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
package io.mosip.certify.api.spi;

import io.mosip.certify.api.dto.AuditDTO;
import io.mosip.certify.api.util.Action;
import io.mosip.certify.api.util.ActionStatus;

public interface AuditPlugin {

    /**
     + Plugin method to audit all the actions in certify service.
     +
     +  @param action Action to audit @{@link Action}
     +  @param actionStatus Action status to audit @{@link ActionStatus}
     +  @param audit @{@link AuditDTO} during this action
     +  @param t Any error / exception occurred during this action, null if no errors / exception found.
     */
    void logAudit(Action action, ActionStatus status, AuditDTO audit, Throwable t);

    /**
    + Plugin method to audit all the actions in certify service.
    +
    +  @param username Session username for audit
    +  @param action Action to audit @{@link Action}
    +  @param actionStatus Action status to audit @{@link ActionStatus}
    +  @param audit @{@link AuditDTO} during this action
    +  @param t Any error / exception occurred during this action, null if no errors / exception found.
    */
	void logAudit(String username, Action action, ActionStatus status, AuditDTO audit, Throwable t);
}
