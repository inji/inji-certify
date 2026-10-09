package io.mosip.certify.services;

import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.dto.CredentialStatusResponse;
import io.mosip.certify.core.dto.UpdateCredentialStatusRequest;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.spi.CredentialStatusService;
import io.mosip.certify.entity.CredentialStatusTransaction;
import io.mosip.certify.entity.StatusListCredential;
import io.mosip.certify.repository.CredentialStatusTransactionRepository;
import io.mosip.certify.repository.StatusListCredentialRepository;
import io.mosip.certify.utils.BitStringStatusListUtils;
import lombok.extern.slf4j.Slf4j;

import java.util.List;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Slf4j
@Service
public class CredentialStatusServiceImpl implements CredentialStatusService {
    @Autowired
    private CredentialStatusTransactionRepository credentialStatusTransactionRepository;

    @Autowired
    private StatusListCredentialRepository statusListCredentialRepository;

    /** Status purposes a deployment allows; the first entry is the default when a request omits it. */
    @Value("#{${mosip.certify.data-provider-plugin.credential-status.allowed-status-purposes:{}}}")
    private List<String> allowedStatusPurposes;

    @Override
    public CredentialStatusResponse updateCredentialStatus(UpdateCredentialStatusRequest request) {
        String statusListCredentialId = request.getCredentialStatus().getStatusListCredential();
        Long statusListIndex = request.getCredentialStatus().getStatusListIndex();
        String id = request.getCredentialStatus().getId();

        if(id != null && !id.equals(statusListCredentialId)) {
            throw new CertifyException(ErrorConstants.STATUS_ID_MISMATCH, "Mismatch between credential status ID and Status List Credential.");
        }
        StatusListCredential statusListCredential = statusListCredentialRepository.findById(statusListCredentialId)
                .orElseThrow(() -> new CertifyException(ErrorConstants.STATUS_LIST_NOT_FOUND, "Status List Credential not found for ID: " + statusListCredentialId));

        // Validate statusPurpose and statusListIndex
        String validatedPurpose = validateCredentialStatus(request.getCredentialStatus().getStatusPurpose(),
                statusListIndex, statusListCredential);

        CredentialStatusTransaction transaction = new CredentialStatusTransaction();
        transaction.setStatusPurpose(validatedPurpose);
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

    private String validateCredentialStatus(String requestedPurpose, Long statusListIndex,
                                            StatusListCredential statusListCredential) {
        // The controller's @Valid binding rejects a null index before it gets here, but this
        // is a public service on an SPI interface: a direct caller skips bean validation, and
        // the unboxing in the comparison below would turn a null into a NullPointerException.
        if (statusListIndex == null) {
            throw new CertifyException(ErrorConstants.INVALID_REQUEST, "statusListIndex is required");
        }

        if (statusListIndex < 0) {
            throw new CertifyException(ErrorConstants.INDEX_OUT_OF_BOUNDS,
                "statusListIndex must be non-negative, received: " + statusListIndex);
        }

        // Validate statusListIndex using shared utility, after the cheap checks above so the
        // KB->bits conversion only runs for an index that could be in range.
        // This ensures the effective 16 KB minimum and overflow/maximum checks match batch processing
        long maxCapacity = BitStringStatusListUtils.safeConvertKBToBits(statusListCredential.getCapacityInKB());

        if (statusListIndex >= maxCapacity) {
            throw new CertifyException(ErrorConstants.INDEX_OUT_OF_BOUNDS,
                "statusListIndex " + statusListIndex + " exceeds maximum capacity " +
                maxCapacity + " for status list '" + statusListCredential.getId() + "'");
        }


        if (allowedStatusPurposes == null || allowedStatusPurposes.isEmpty()) {
            throw new CertifyException(ErrorConstants.INVALID_STATUS_PURPOSE,
                "No status purpose is configured in this environment.");
        }
    
        if (StringUtils.isEmpty(requestedPurpose)) {
            return allowedStatusPurposes.getFirst();
        }
        if (!allowedStatusPurposes.contains(requestedPurpose)) {
            throw new CertifyException(ErrorConstants.INVALID_STATUS_PURPOSE,
                "Invalid status purpose '" + requestedPurpose + "'. Allowed values are: " + allowedStatusPurposes);
        }
        return requestedPurpose;
    }
}
