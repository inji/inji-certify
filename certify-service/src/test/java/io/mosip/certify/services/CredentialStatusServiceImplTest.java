package io.mosip.certify.services;

import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.dto.CredentialStatusResponse;
import io.mosip.certify.core.dto.UpdateCredentialStatusRequest;
import io.mosip.certify.core.dto.UpdateCredentialStatusRequestV2;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.entity.CredentialStatusTransaction;
import io.mosip.certify.entity.Ledger;
import io.mosip.certify.core.dto.CredentialStatusDetail;
import io.mosip.certify.entity.StatusListCredential;
import io.mosip.certify.repository.CredentialStatusTransactionRepository;
import io.mosip.certify.repository.LedgerRepository;
import io.mosip.certify.repository.StatusListCredentialRepository;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.junit.Assert.*;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class CredentialStatusServiceImplTest {
    @Mock
    private LedgerRepository ledgerRepository;
    @Mock
    private CredentialStatusTransactionRepository credentialStatusTransactionRepository;
    @Mock
    private StatusListCredentialRepository statusListCredentialRepository;

    @InjectMocks
    private CredentialStatusServiceImpl credentialStatusService;

    @Before
    public void setUp() {
        MockitoAnnotations.openMocks(this);
        ReflectionTestUtils.setField(credentialStatusService, "allowedCredentialStatusPurposes", List.of("revocation", "purpose2"));
    }

    @Test
    public void updateCredential_CredentialIdNotFound_ThrowsException() {
        String credentialId = "124";
        String statusListCredential = "https://example.com/status-list/xyz";
        UpdateCredentialStatusRequest request = createValidUpdateCredentialRequest(credentialId, statusListCredential);

        when(ledgerRepository.findByCredentialId(credentialId)).thenReturn(Optional.empty());

        RuntimeException exception = assertThrows(RuntimeException.class, () -> {
            credentialStatusService.updateCredentialStatus(request);
        });

        assertEquals("404 NOT_FOUND \"Credential not found: " + credentialId + "\"", exception.getMessage());
    }

    @Test
    public void updateCredential_With_ExistingTransaction() {
        String credentialId = "67823e96-fda0-4eba-9828-a32a8d22cc45";
        String statusListCredential = "https://example.com/status-list/xyz";
        UpdateCredentialStatusRequest request = createValidUpdateCredentialRequest(credentialId, statusListCredential);

        Ledger ledger = createLedger(credentialId);

        CredentialStatusDetail detail = new CredentialStatusDetail();
        detail.setStatusListCredentialId(statusListCredential);
        detail.setStatusListIndex(87823L);
        detail.setStatusPurpose("revocation");
        detail.setCreatedTimes(System.currentTimeMillis());
        ledger.getCredentialStatusDetails().add(detail);

        // ADD StatusListCredential mock
        StatusListCredential statusListCredentialEntity = new StatusListCredential();
        statusListCredentialEntity.setId(statusListCredential);
        statusListCredentialEntity.setCapacityInKB(16L); // Large enough for index 87823

        CredentialStatusTransaction existingTransaction = new CredentialStatusTransaction();
        existingTransaction.setTransactionLogId(42L);
        existingTransaction.setCredentialId(credentialId);
        existingTransaction.setStatusPurpose("revocation");
        existingTransaction.setStatusValue(true);
        existingTransaction.setStatusListCredentialId(statusListCredential);
        existingTransaction.setStatusListIndex(87823L);

        when(ledgerRepository.findByCredentialId(credentialId)).thenReturn(Optional.of(ledger));
        when(statusListCredentialRepository.findById(statusListCredential))
                .thenReturn(Optional.of(statusListCredentialEntity)); // ADD THIS
        when(credentialStatusTransactionRepository.save(any())).thenAnswer(invocation -> invocation.getArgument(0));

        CredentialStatusResponse result = credentialStatusService.updateCredentialStatus(request);

        assertNotNull(result);
        assertEquals(credentialId, result.getCredentialId());
        assertEquals("revocation", result.getStatusPurpose());
        assertEquals(87823, result.getStatusListIndex().longValue());
        assertEquals(statusListCredential, result.getStatusListCredentialUrl());
    }

    @Test
    public void updateCredential_WithValidRequest_UpdatesLedgerAndReturnsResponse() {
        String credentialId = "67823e96-fda0-4eba-9828-a32a8d22cc42";
        String statusListCredential = "https://example.com/status-list/xyz";

        UpdateCredentialStatusRequest request = createValidUpdateCredentialRequest(credentialId, statusListCredential);
        Ledger ledger = createLedger(credentialId);

        CredentialStatusDetail detail = new CredentialStatusDetail();
        detail.setStatusListCredentialId(statusListCredential);
        detail.setStatusListIndex(87823L);
        detail.setStatusPurpose("revocation");
        detail.setCreatedTimes(System.currentTimeMillis());
        ledger.getCredentialStatusDetails().add(detail);

        // ADD StatusListCredential mock
        StatusListCredential statusListCredentialEntity = new StatusListCredential();
        statusListCredentialEntity.setId(statusListCredential);
        statusListCredentialEntity.setCapacityInKB(16L); // Large enough for index 87823

        CredentialStatusTransaction savedTransaction = createSavedTransaction(credentialId, statusListCredential);

        when(ledgerRepository.findByCredentialId(credentialId)).thenReturn(Optional.of(ledger));
        when(statusListCredentialRepository.findById(statusListCredential))
                .thenReturn(Optional.of(statusListCredentialEntity)); // ADD THIS
        when(credentialStatusTransactionRepository.save(any(CredentialStatusTransaction.class)))
                .thenReturn(savedTransaction);

        CredentialStatusResponse result = credentialStatusService.updateCredentialStatus(request);

        assertNotNull(result);
        assertEquals(credentialId, result.getCredentialId());
        assertEquals("revocation", result.getStatusPurpose());
        assertEquals(87823, result.getStatusListIndex().longValue());
        assertEquals("VerifiableCredential", result.getCredentialType());
        assertEquals(statusListCredential, result.getStatusListCredentialUrl());
        assertNotNull(result.getStatusTimestamp());

        verify(ledgerRepository).findByCredentialId(credentialId);
        verify(statusListCredentialRepository).findById(statusListCredential); // ADD THIS
        verify(credentialStatusTransactionRepository).save(any(CredentialStatusTransaction.class));
    }


    @Test
    public void updateCredentialStatus_NullStatusPurpose_AllowsUpdate() {
        String credentialId = "cid-002";
        String statusListCredential = "https://example.com/status-list/def";
        UpdateCredentialStatusRequest request = createValidUpdateCredentialRequest(credentialId, statusListCredential);
        request.getCredentialStatus().setStatusPurpose(null);

        Ledger ledger = createLedger(credentialId);

        CredentialStatusDetail detail = new CredentialStatusDetail();
        detail.setStatusListCredentialId(statusListCredential);
        detail.setStatusListIndex(87823L);
        detail.setStatusPurpose(null);
        detail.setCreatedTimes(System.currentTimeMillis());
        ledger.getCredentialStatusDetails().add(detail);

        // ADD StatusListCredential mock
        StatusListCredential statusListCredentialEntity = new StatusListCredential();
        statusListCredentialEntity.setId(statusListCredential);
        statusListCredentialEntity.setCapacityInKB(16L);

        when(ledgerRepository.findByCredentialId(credentialId)).thenReturn(Optional.of(ledger));
        when(statusListCredentialRepository.findById(statusListCredential))
                .thenReturn(Optional.of(statusListCredentialEntity)); // ADD THIS
        when(credentialStatusTransactionRepository.save(any())).thenAnswer(invocation -> invocation.getArgument(0));

        CredentialStatusResponse response = credentialStatusService.updateCredentialStatus(request);
        assertNotNull(response);
        assertEquals(credentialId, response.getCredentialId());
        assertEquals("revocation", response.getStatusPurpose()); // Will be default "revocation"
    }


    private UpdateCredentialStatusRequest createValidUpdateCredentialRequest(String credentialId, String statusListCredential) {
        UpdateCredentialStatusRequest.CredentialStatusDto statusDto = new UpdateCredentialStatusRequest.CredentialStatusDto();
        statusDto.setId(statusListCredential + "#87823");
        statusDto.setType("BitstringStatusListEntry");
        statusDto.setStatusPurpose("revocation");
        statusDto.setStatusListIndex(87823L);
        statusDto.setStatusListCredential(statusListCredential);

        UpdateCredentialStatusRequest request = new UpdateCredentialStatusRequest();
        request.setCredentialId(credentialId);
        request.setCredentialStatus(statusDto);
        request.setStatus(true); // Mark as revoked

        return request;
    }

    private CredentialStatusTransaction createSavedTransaction(String credentialId, String statusListCredential) {
        CredentialStatusTransaction transaction = new CredentialStatusTransaction();
        transaction.setCredentialId(credentialId);
        transaction.setStatusPurpose("revocation");
        transaction.setStatusValue(true);
        transaction.setStatusListCredentialId(statusListCredential);
        transaction.setStatusListIndex(87823L);
        transaction.setCreatedDtimes(LocalDateTime.parse("2025-06-11T11:41:30.236"));
        return transaction;
    }

    private Ledger createLedger(String credentialId) {
        Ledger ledger = new Ledger();
        ledger.setId(1L);
        ledger.setCredentialId(credentialId);
        ledger.setIssuerId("did:web:Nandeesh778.github.io:local-test:certify_did");
        ledger.setIssuanceDate(LocalDateTime.parse("2025-06-11T11:41:30.236"));
        ledger.setExpirationDate(null);
        ledger.setCredentialType("VerifiableCredential");
        ledger.setCredentialStatusDetails(new ArrayList<>());
        return ledger;
    }

    @Test
    public void updateCredentialStatus_ValidRequest_Success() {
        String credentialId = "9f4a4c50-2e6c-4e72-9fd3-8a9e67f1f6c";
        String statusListCredentialId = "status-list-1";

        UpdateCredentialStatusRequest.CredentialStatusDto statusDto =
                new UpdateCredentialStatusRequest.CredentialStatusDto();
        statusDto.setStatusPurpose("revocation");
        statusDto.setStatusListIndex(5L); // ADD THIS - was missing
        statusDto.setStatusListCredential(statusListCredentialId); // ADD THIS

        UpdateCredentialStatusRequest request = new UpdateCredentialStatusRequest();
        request.setCredentialId(credentialId);
        request.setCredentialStatus(statusDto);
        request.setStatus(true);

        Ledger ledger = createLedger(credentialId);
        ledger.setIssuerId("did:web:example.com:issue");

        CredentialStatusDetail detail = new CredentialStatusDetail();
        detail.setStatusListCredentialId(statusListCredentialId);
        detail.setStatusListIndex(5L);
        detail.setStatusPurpose("revocation");
        detail.setCreatedTimes(System.currentTimeMillis());
        ledger.getCredentialStatusDetails().add(detail);

        StatusListCredential statusListCredential = new StatusListCredential();
        statusListCredential.setId(statusListCredentialId);
        statusListCredential.setCapacityInKB(1L);

        CredentialStatusTransaction savedTransaction = new CredentialStatusTransaction();
        savedTransaction.setCredentialId(credentialId);
        savedTransaction.setStatusPurpose("revocation");
        savedTransaction.setStatusValue(true);
        savedTransaction.setStatusListCredentialId(statusListCredentialId);
        savedTransaction.setStatusListIndex(5L);
        savedTransaction.setCreatedDtimes(LocalDateTime.parse("2025-06-11T12:00:00.000"));

        when(ledgerRepository.findByCredentialId(credentialId)).thenReturn(Optional.of(ledger));
        when(statusListCredentialRepository.findById(statusListCredentialId))
                .thenReturn(Optional.of(statusListCredential));
        when(credentialStatusTransactionRepository.save(any(CredentialStatusTransaction.class)))
                .thenReturn(savedTransaction);

        CredentialStatusResponse response = credentialStatusService.updateCredentialStatus(request);

        assertNotNull(response);
        assertEquals(credentialId, response.getCredentialId());
        assertEquals("did:web:example.com:issue", response.getIssuerId());
        assertEquals("VerifiableCredential", response.getCredentialType());
        assertEquals(ledger.getIssuanceDate(), response.getIssueDate());
        assertNull(response.getExpirationDate());
        assertEquals(statusListCredentialId, response.getStatusListCredentialUrl());
        assertEquals(5L, response.getStatusListIndex().longValue());
        assertEquals("revocation", response.getStatusPurpose());
        assertEquals(savedTransaction.getCreatedDtimes(), response.getStatusTimestamp());

        verify(ledgerRepository).findByCredentialId(credentialId);
        verify(statusListCredentialRepository).findById(statusListCredentialId);
        verify(credentialStatusTransactionRepository).save(any(CredentialStatusTransaction.class));
    }


    @Test
    public void updateCredentialStatus_MissingCredentialStatusDetails_ThrowsCertifyException() {
        String credentialId = "9f4a4c50-2e6c-4e72-9fd3-8a9e67f1f6c";

        UpdateCredentialStatusRequest.CredentialStatusDto statusDto =
                new UpdateCredentialStatusRequest.CredentialStatusDto();
        statusDto.setStatusPurpose("revocation");

        UpdateCredentialStatusRequest request = new UpdateCredentialStatusRequest();
        request.setCredentialId(credentialId);
        request.setCredentialStatus(statusDto);
        request.setStatus(true);

        Ledger ledger = createLedger(credentialId);

        when(ledgerRepository.findByCredentialId(credentialId)).thenReturn(Optional.of(ledger));

        CertifyException ex = assertThrows(
                CertifyException.class,
                () -> credentialStatusService.updateCredentialStatus(request)
        );

        assertEquals(ErrorConstants.MISSING_CREDENTIAL_STATUS_DETAILS, ex.getErrorCode());
        verify(ledgerRepository).findByCredentialId(credentialId);
    }

    @Test
    public void updateCredentialStatusV2_ValidRequest_Success() {
        String statusListCredentialId = "status-list-2";
        Long statusListIndex = 10L;

        UpdateCredentialStatusRequestV2.CredentialStatusDtoV2 statusDto =
                new UpdateCredentialStatusRequestV2.CredentialStatusDtoV2();
        statusDto.setStatusListCredential(statusListCredentialId);
        statusDto.setStatusListIndex(statusListIndex);
        statusDto.setStatusPurpose("revocation");
        statusDto.setType("BitstringStatusListEntry");
        statusDto.setId(statusListCredentialId);

        UpdateCredentialStatusRequestV2 request = new UpdateCredentialStatusRequestV2();
        request.setCredentialStatus(statusDto);
        request.setStatus(false);

        StatusListCredential statusListCredential = new StatusListCredential();
        statusListCredential.setId(statusListCredentialId);
        statusListCredential.setCapacityInKB(1L);

        CredentialStatusTransaction savedTransaction = new CredentialStatusTransaction();
        savedTransaction.setStatusPurpose("revocation");
        savedTransaction.setStatusValue(false);
        savedTransaction.setStatusListCredentialId(statusListCredentialId);
        savedTransaction.setStatusListIndex(statusListIndex);
        savedTransaction.setCreatedDtimes(LocalDateTime.parse("2025-06-11T12:05:00.000"));

        when(statusListCredentialRepository.findById(statusListCredentialId))
                .thenReturn(Optional.of(statusListCredential));
        when(credentialStatusTransactionRepository.save(any(CredentialStatusTransaction.class)))
                .thenReturn(savedTransaction);

        CredentialStatusResponse response = credentialStatusService.updateCredentialStatusV2(request);

        assertNotNull(response);
        assertEquals(statusListCredentialId, response.getStatusListCredentialUrl());
        assertEquals(statusListIndex.longValue(), response.getStatusListIndex().longValue());
        assertEquals("revocation", response.getStatusPurpose());
        assertEquals("BitstringStatusListEntry", response.getCredentialType());
        assertEquals(savedTransaction.getCreatedDtimes(), response.getStatusTimestamp());

        verify(statusListCredentialRepository).findById(statusListCredentialId);
        verify(credentialStatusTransactionRepository).save(any(CredentialStatusTransaction.class));
    }

    @Test
    public void updateCredentialStatusV2_NegativeIndex_ThrowsCertifyException() {
        String statusListCredentialId = "status-list-negative";
        Long statusListIndex = -1L;

        UpdateCredentialStatusRequestV2.CredentialStatusDtoV2 statusDto =
                new UpdateCredentialStatusRequestV2.CredentialStatusDtoV2();
        statusDto.setStatusListCredential(statusListCredentialId);
        statusDto.setStatusListIndex(statusListIndex);
        statusDto.setStatusPurpose("revocation");
        statusDto.setId(statusListCredentialId);

        UpdateCredentialStatusRequestV2 request = new UpdateCredentialStatusRequestV2();
        request.setCredentialStatus(statusDto);
        request.setStatus(true);

        StatusListCredential statusListCredential = new StatusListCredential();
        statusListCredential.setId(statusListCredentialId);
        statusListCredential.setCapacityInKB(1L);

        when(statusListCredentialRepository.findById(statusListCredentialId))
                .thenReturn(Optional.of(statusListCredential));

        CertifyException ex = assertThrows(
                CertifyException.class,
                () -> credentialStatusService.updateCredentialStatusV2(request)
        );

        assertEquals(ErrorConstants.INVALID_STATUS_LIST_INDEX, ex.getErrorCode());
        verify(statusListCredentialRepository).findById(statusListCredentialId);
    }

    @Test
    public void updateCredentialStatusV2_IndexOutOfRange_ThrowsCertifyException() {
        String statusListCredentialId = "status-list-out-of-range";
        Long statusListIndex = 9000L;

        UpdateCredentialStatusRequestV2.CredentialStatusDtoV2 statusDto =
                new UpdateCredentialStatusRequestV2.CredentialStatusDtoV2();
        statusDto.setStatusListCredential(statusListCredentialId);
        statusDto.setStatusListIndex(statusListIndex);
        statusDto.setStatusPurpose("revocation");
        statusDto.setId(statusListCredentialId);

        UpdateCredentialStatusRequestV2 request = new UpdateCredentialStatusRequestV2();
        request.setCredentialStatus(statusDto);
        request.setStatus(true);

        StatusListCredential statusListCredential = new StatusListCredential();
        statusListCredential.setId(statusListCredentialId);
        statusListCredential.setCapacityInKB(1L); // list size = 1 * 1024 * 8 = 8192 (indices 0-8191)

        when(statusListCredentialRepository.findById(statusListCredentialId))
                .thenReturn(Optional.of(statusListCredential));

        CertifyException ex = assertThrows(
                CertifyException.class,
                () -> credentialStatusService.updateCredentialStatusV2(request)
        );

        assertEquals(ErrorConstants.STATUS_LIST_INDEX_OUT_OF_RANGE, ex.getErrorCode());
        verify(statusListCredentialRepository).findById(statusListCredentialId);
    }

}