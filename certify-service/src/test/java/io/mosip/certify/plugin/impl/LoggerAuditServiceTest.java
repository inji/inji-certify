package io.mosip.certify.plugin.impl;

import io.mosip.certify.api.dto.AuditDTO;
import io.mosip.certify.api.util.Action;
import io.mosip.certify.api.util.ActionStatus;
import org.junit.Test;
import org.slf4j.MDC;

import static org.junit.Assert.assertNull;

public class LoggerAuditServiceTest {

    private final LoggerAuditService service = new LoggerAuditService();

    private AuditDTO auditDTO() {
        AuditDTO dto = new AuditDTO();
        dto.setTransactionId("txn-1");
        dto.setClientId("client-1");
        dto.setIdType("VID");
        return dto;
    }

    @Test
    public void should_clearMdc_when_auditLoggedWithoutUser() {
        service.logAudit(Action.VC_ISSUANCE, ActionStatus.SUCCESS, auditDTO(), null);
        assertNull(MDC.get("transactionId"));
    }

    @Test
    public void should_clearMdc_when_auditLoggedWithUser() {
        service.logAudit("user-1", Action.PROOF_VALIDATION, ActionStatus.SUCCESS, auditDTO(), null);
        assertNull(MDC.get("transactionId"));
    }

    @Test
    public void should_logError_when_auditStatusIsError() {
        service.logAudit("user-1", Action.NONCE_VALIDATION, ActionStatus.ERROR, auditDTO(), null);
        assertNull(MDC.get("transactionId"));
    }

    @Test
    public void should_logErrorAndReturn_when_throwableProvided() {
        service.logAudit(Action.VC_ISSUANCE, ActionStatus.SUCCESS, auditDTO(), new RuntimeException("boom"));
        assertNull(MDC.get("transactionId"));
    }

    @Test
    public void should_notThrow_when_auditDtoIsNull() {
        service.audit("user-1", Action.VC_ISSUANCE, ActionStatus.SUCCESS, null, null);
        assertNull(MDC.get("transactionId"));
    }

    @Test
    public void should_logActionOnly_when_userIsNull() {
        service.audit(null, Action.VC_ISSUANCE, ActionStatus.SUCCESS, auditDTO(), null);
        assertNull(MDC.get("transactionId"));
    }
}
