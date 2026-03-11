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
        String resolvedPurpose = null;
        if (request.getCredentialStatus() != null) {
            resolvedPurpose = resolveAndValidateStatusPurpose(request.getCredentialStatus().getStatusPurpose());
        }

        Ledger ledger = ledgerRepository.findByCredentialId(request.getCredentialId())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND,"Credential not found: " + request.getCredentialId()));

        if(ledger.getCredentialStatusDetails() == null || ledger.getCredentialStatusDetails().isEmpty()) {
            throw new CertifyException(ErrorConstants.MISSING_CREDENTIAL_STATUS_DETAILS, "CredentialStatus details are missing in the issued credential.");
        }

        CredentialStatusDetail credentialStatusDetail = ledger.getCredentialStatusDetails().getFirst();

        if (request.getCredentialStatus() != null &&
                request.getCredentialStatus().getStatusListIndex() != null &&
                !request.getCredentialStatus().getStatusListIndex()
                        .equals(credentialStatusDetail.getStatusListIndex())) {
            throw new CertifyException(
                    ErrorConstants.STATUS_LIST_INDEX_OUT_OF_RANGE,
                    "Requested statusListIndex does not match the issued credential."
            );
        }

        StatusListCredential statusListCredential = statusListCredentialRepository.findById(credentialStatusDetail.getStatusListCredentialId())
                .orElseThrow(() -> new CertifyException(ErrorConstants.STATUS_LIST_NOT_FOUND, "Status List Credential not found for ID: " + credentialStatusDetail.getStatusListCredentialId()));

        validateStatusListIndex(credentialStatusDetail.getStatusListIndex(), statusListCredential);

        CredentialStatusTransaction transaction = new CredentialStatusTransaction();
        transaction.setCredentialId(ledger.getCredentialId());
        transaction.setStatusPurpose(resolvedPurpose);
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
        String resolvedPurpose = resolveAndValidateStatusPurpose(request.getCredentialStatus().getStatusPurpose());

        String statusListCredentialId = request.getCredentialStatus().getStatusListCredential();
        Long statusListIndex = request.getCredentialStatus().getStatusListIndex();

        String id = request.getCredentialStatus().getId();

        if(id != null && !id.equals(statusListCredentialId)) {
            throw new CertifyException(ErrorConstants.STATUS_ID_MISMATCH, "Mismatch between credential status ID and Status List Credential.");
        }
        StatusListCredential statusListCredential = statusListCredentialRepository.findById(statusListCredentialId)
                .orElseThrow(() -> new CertifyException(ErrorConstants.STATUS_LIST_NOT_FOUND, "Status List Credential not found for ID: " + statusListCredentialId));

        validateStatusListIndex(statusListIndex, statusListCredential);

        CredentialStatusTransaction transaction = new CredentialStatusTransaction();
        transaction.setStatusPurpose(resolvedPurpose);
        transaction.setStatusValue(request.getStatus());
        transaction.setStatusListCredentialId(statusListCredentialId);
        transaction.setStatusListIndex(statusListIndex);
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

    private String resolveAndValidateStatusPurpose(String rawPurpose) {
        if(rawPurpose == null) {
            return Constants.DEFAULT_STATUS_PURPOSE;
        }
        String statusPurposeValue = rawPurpose.trim();
        if(statusPurposeValue.isEmpty()) {
            throw new CertifyException(ErrorConstants.INVALID_STATUS_PURPOSE, "statusPurpose must not be empty");
        }
        boolean supported = allowedCredentialStatusPurposes != null && allowedCredentialStatusPurposes.stream().anyMatch(p -> p.equalsIgnoreCase(statusPurposeValue));
        if(!supported) {
            throw new CertifyException((ErrorConstants.INVALID_STATUS_PURPOSE, "Unsupported statusPurpose: " + statusPurposeValue);
        }
        return statusPurposeValue.toLowerCase();
    }

    private void validateStatusListIndex(Long statusListIndex, StatusListCredential statusListCredential) {
        if (statusListIndex == null) {
            throw new CertifyException(ErrorConstants.INVALID_STATUS_LIST_INDEX, "statusListIndex must not be null");
        }
        if(statusListIndex < 0) {
            throw new CertifyException(ErrorConstants.INVALID_STATUS_LIST_INDEX, "statusListIndex must be a non-negative integer");
        }
        long listSize = getStatusListSize(statusListCredential);
        if(statusListIndex >= listSize) {
            String errorMsg = String.format("statusListIndex must be between 0 and %d for status list %s", listSize - 1, statusListCredential.getId());
            throw new CertifyException(ErrorConstants.STATUS_LIST_INDEX_OUT_OF_RANGE, errorMsg);
        }
    }

    private long getStatusListSize(StatusListCredential statusListCredential) {
        try {
            Long capacityInKB = statusListCredential.getCapacityInKB();
            if(capacityInKB == null) {
                return 131072;
            }
            return capacityInKB * 1024 * 8;
        }
        catch (Exception e) {
            throw new CertifyException(ErrorConstants.INVALID_STATUS_LIST_CONFIGURATION,
                    "Unable to determine status list size for credential: " + statusListCredential.getId()
            );
        }
    }
}
