package io.mosip.certify.services;

import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.dto.CredentialStatusResponse;
import io.mosip.certify.core.dto.UpdateCredentialStatusRequest;
import io.mosip.certify.core.dto.UpdateCredentialStatusRequestV2;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.spi.CredentialStatusService;
import io.mosip.certify.entity.CredentialStatusTransaction;
import io.mosip.certify.entity.Ledger;
import io.mosip.certify.core.dto.CredentialStatusDetail;
import io.mosip.certify.entity.StatusListCredential;
import io.mosip.certify.repository.CredentialStatusTransactionRepository;
import io.mosip.certify.repository.LedgerRepository;
import io.mosip.certify.repository.StatusListCredentialRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;

@Slf4j
@Service
public class CredentialStatusServiceImpl implements CredentialStatusService {
    public static final int DEFAULT_STATUS_LIST_SIZE = 131072;

    @Autowired
    private LedgerRepository ledgerRepository;

    @Autowired
    private CredentialStatusTransactionRepository credentialStatusTransactionRepository;

    @Autowired
    private StatusListCredentialRepository statusListCredentialRepository;

    @Value("#{${mosip.certify.data-provider-plugin.credential-status.allowed-status-purposes:{}}}")
    private List<String> allowedCredentialStatusPurposes;

    @Override
    public CredentialStatusResponse updateCredentialStatus(UpdateCredentialStatusRequest request) {
        String statusPurpose = validateAndGetStatusPurpose(request.getCredentialStatus() == null ? null : request.getCredentialStatus().getStatusPurpose());
        validateStatusListIndex(request.getCredentialStatus().getStatusListIndex());

        Ledger ledger = ledgerRepository.findByCredentialId(request.getCredentialId())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND,"Credential not found: " + request.getCredentialId()));

        if(ledger.getCredentialStatusDetails() == null || ledger.getCredentialStatusDetails().isEmpty()) {
            throw new CertifyException(ErrorConstants.MISSING_CREDENTIAL_STATUS_DETAILS, "CredentialStatus details are missing in the issued credential.");
        }

        CredentialStatusDetail credentialStatusDetail = ledger.getCredentialStatusDetails().getFirst();

        CredentialStatusTransaction transaction = new CredentialStatusTransaction();
        transaction.setCredentialId(ledger.getCredentialId());
        transaction.setStatusPurpose(statusPurpose);
        transaction.setStatusValue(request.getStatus());
        transaction.setStatusListCredentialId(credentialStatusDetail.getStatusListCredentialId());
        transaction.setStatusListIndex(credentialStatusDetail.getStatusListIndex());
        CredentialStatusTransaction savedTransaction =credentialStatusTransactionRepository.save(transaction);

        CredentialStatusResponse dto = new CredentialStatusResponse();
        dto.setCredentialId(ledger.getCredentialId());
        dto.setIssuerId(ledger.getIssuerId());
        dto.setCredentialType(ledger.getCredentialType());
        dto.setIssueDate(ledger.getIssuanceDate());
        dto.setExpirationDate(ledger.getExpirationDate());
        dto.setStatusListCredentialUrl(credentialStatusDetail.getStatusListCredentialId());
        dto.setStatusListIndex(credentialStatusDetail.getStatusListIndex());
        dto.setStatusPurpose(transaction.getStatusPurpose());
        dto.setStatusTimestamp(savedTransaction.getCreatedDtimes());
        return dto;
    }

    @Override
    public CredentialStatusResponse updateCredentialStatusV2(UpdateCredentialStatusRequestV2 request) {
        if (request.getCredentialStatus() == null) {
            throw new CertifyException(ErrorConstants.INVALID_REQUEST, "credentialStatus must not be null");
        }
        String statusPurpose = validateAndGetStatusPurpose(request.getCredentialStatus().getStatusPurpose());
        validateStatusListIndex(request.getCredentialStatus().getStatusListIndex());

        String statusListCredentialId = request.getCredentialStatus().getStatusListCredential();

        String id = request.getCredentialStatus().getId();

        if(id != null && !id.equals(statusListCredentialId)) {
            throw new CertifyException(ErrorConstants.STATUS_ID_MISMATCH, "Mismatch between credential status ID and Status List Credential.");
        }
        StatusListCredential statusListCredential = statusListCredentialRepository.findById(statusListCredentialId)
                .orElseThrow(() -> new CertifyException(ErrorConstants.STATUS_LIST_NOT_FOUND, "Status List Credential not found for ID: " + statusListCredentialId));


        CredentialStatusTransaction transaction = new CredentialStatusTransaction();
        transaction.setStatusPurpose(statusPurpose);
        transaction.setStatusValue(request.getStatus());
        transaction.setStatusListCredentialId(statusListCredentialId);
        transaction.setStatusListIndex(request.getCredentialStatus().getStatusListIndex());
        CredentialStatusTransaction savedTransaction =credentialStatusTransactionRepository.save(transaction);

        CredentialStatusResponse dto = new CredentialStatusResponse();
        dto.setStatusListCredentialUrl(transaction.getStatusListCredentialId());
        dto.setStatusListIndex(transaction.getStatusListIndex());
        dto.setStatusPurpose(transaction.getStatusPurpose());
        dto.setStatusTimestamp(savedTransaction.getCreatedDtimes());
        if(request.getCredentialStatus().getType() != null) {
            dto.setCredentialType(request.getCredentialStatus().getType());
        }
        return dto;
    }

    private String validateAndGetStatusPurpose(String statusPurpose) {
        if(statusPurpose == null || statusPurpose.trim().isEmpty()) {
            return allowedCredentialStatusPurposes.get(0);
        }
        String statusPurposeValue = statusPurpose.trim().toLowerCase();
        if(allowedCredentialStatusPurposes == null || allowedCredentialStatusPurposes.isEmpty()) {
            throw new CertifyException(ErrorConstants.INVALID_STATUS_PURPOSE, "No allowed status purposes configured.");
        }
        boolean isAllowed = allowedCredentialStatusPurposes.stream()
                .anyMatch(allowed -> allowed.equalsIgnoreCase(statusPurposeValue));
        if (!isAllowed) {
            throw new CertifyException(ErrorConstants.INVALID_STATUS_PURPOSE,
                    "statusPurpose must be one of: " + allowedCredentialStatusPurposes);
        }
        return statusPurposeValue;
    }

    private void validateStatusListIndex(Long statusListIndex) {
        if (statusListIndex == null) {
            throw new CertifyException(ErrorConstants.INVALID_STATUS_LIST_INDEX, "statusListIndex must not be null");
        }
        if(statusListIndex < 0) {
            throw new CertifyException(ErrorConstants.INVALID_STATUS_LIST_INDEX, "statusListIndex must be a non-negative integer");
        }
        if(statusListIndex >= DEFAULT_STATUS_LIST_SIZE) {
            String errorMsg = String.format("statusListIndex must be between 0 and %d", DEFAULT_STATUS_LIST_SIZE - 1);
            throw new CertifyException(ErrorConstants.STATUS_LIST_INDEX_OUT_OF_RANGE, errorMsg);
        }
    }

}
