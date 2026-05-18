package io.mosip.certify.services;

import io.mosip.certify.core.dto.CredentialStatusResponse;
import io.mosip.certify.core.dto.UpdateCredentialStatusRequest;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.entity.CredentialStatusTransaction;
import io.mosip.certify.entity.StatusListCredential;
import io.mosip.certify.repository.CredentialStatusTransactionRepository;
import io.mosip.certify.repository.StatusListCredentialRepository;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.junit.MockitoJUnitRunner;

import java.util.Optional;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class CredentialStatusServiceImplTest {
    @Mock
    private CredentialStatusTransactionRepository credentialStatusTransactionRepository;

    @Mock
    private StatusListCredentialRepository statusListCredentialRepository;

    @InjectMocks
    private CredentialStatusServiceImpl credentialStatusService;

    @Before
    public void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    public void updateCredentialStatusV2_StatusIdMismatch_ThrowsException() {
        String statusListCredential = "https://example.com/status-list/xyz#87823";
        UpdateCredentialStatusRequest request = createValidUpdateCredentialRequest(statusListCredential);
        request.getCredentialStatus().setId("https://example.com/status-list/abc#12345"); // Mismatched ID

        CertifyException exception = assertThrows(CertifyException.class, () -> {
            credentialStatusService.updateCredentialStatus(request);
        });

        assertEquals("status_id_mismatch", exception.getErrorCode());
        assertEquals("Mismatch between credential status ID and Status List Credential.", exception.getMessage());
    }

    @Test
    public void updateCredentialStatusV2_StatusListNotFound_ThrowsException() {
        String statusListCredential = "https://example.com/status-list/xyz#87823";
        UpdateCredentialStatusRequest request = createValidUpdateCredentialRequest(statusListCredential);

        when(statusListCredentialRepository.findById(statusListCredential)).thenReturn(Optional.empty());

        CertifyException exception = assertThrows(CertifyException.class, () -> {
            credentialStatusService.updateCredentialStatus(request);
        });

        assertEquals("status_list_not_found_for_the_given_id", exception.getErrorCode());
        assertEquals("Status List Credential not found for ID: " + statusListCredential, exception.getMessage());
    }

    @Test
    public void updateCredentialStatusV2_NullStatusPurpose_UsesStatusListCredentialPurpose() {
        String statusListCredential = "https://example.com/status-list/xyz#87823";
        UpdateCredentialStatusRequest request = createValidUpdateCredentialRequest(statusListCredential);
        request.getCredentialStatus().setStatusPurpose(null); // Null status purpose

        StatusListCredential mockStatusListCredential = new StatusListCredential();
        mockStatusListCredential.setStatusPurpose("revocation");

        when(statusListCredentialRepository.findById(statusListCredential)).thenReturn(Optional.of(mockStatusListCredential));
        when(credentialStatusTransactionRepository.save(any(CredentialStatusTransaction.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        CredentialStatusResponse response = credentialStatusService.updateCredentialStatus(request);

        assertNotNull(response);
        assertEquals("revocation", response.getStatusPurpose());
    }

    @Test
    public void updateCredentialStatusV2_ValidRequest_ReturnsResponse() {
        String statusListCredential = "https://example.com/status-list/xyz#87823";
        UpdateCredentialStatusRequest request = createValidUpdateCredentialRequest(statusListCredential);

        StatusListCredential mockStatusListCredential = new StatusListCredential();
        mockStatusListCredential.setStatusPurpose("revocation");

        when(statusListCredentialRepository.findById(statusListCredential)).thenReturn(Optional.of(mockStatusListCredential));
        when(credentialStatusTransactionRepository.save(any(CredentialStatusTransaction.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        CredentialStatusResponse response = credentialStatusService.updateCredentialStatus(request);

        assertNotNull(response);
        assertEquals(statusListCredential, response.getStatusListCredentialUrl());
        assertEquals("revocation", response.getStatusPurpose());
        assertEquals(87823L, response.getStatusListIndex());
    }

    @Test
    public void updateCredentialStatusV2_NullStatusListCredential_ThrowsException() {
        UpdateCredentialStatusRequest request = createValidUpdateCredentialRequest(null); // Null StatusListCredential

        CertifyException exception = assertThrows(CertifyException.class, () -> {
            credentialStatusService.updateCredentialStatus(request);
        });

        assertEquals("status_list_not_found_for_the_given_id", exception.getErrorCode());
        assertEquals("Status List Credential not found for ID: null", exception.getMessage());
    }

    @Test
    public void updateCredentialStatusV2_NullStatusListIndex_ThrowsException() {
        String statusListCredential = "https://example.com/status-list/xyz#87823";
        UpdateCredentialStatusRequest request = createValidUpdateCredentialRequest(statusListCredential);
        request.getCredentialStatus().setStatusListIndex(null); // Null StatusListIndex

        CertifyException exception = assertThrows(CertifyException.class, () -> {
            credentialStatusService.updateCredentialStatus(request);
        });

        assertEquals("status_list_not_found_for_the_given_id", exception.getErrorCode());
        assertEquals("Status List Credential not found for ID: https://example.com/status-list/xyz#87823", exception.getMessage());
    }

    @Test
    public void updateCredentialStatusV2_EmptyStatusPurpose_UsesStatusListCredentialPurpose() {
        String statusListCredential = "https://example.com/status-list/xyz#87823";
        UpdateCredentialStatusRequest request = createValidUpdateCredentialRequest(statusListCredential);
        request.getCredentialStatus().setStatusPurpose(""); // Empty StatusPurpose

        StatusListCredential mockStatusListCredential = new StatusListCredential();
        mockStatusListCredential.setStatusPurpose("revocation");

        when(statusListCredentialRepository.findById(statusListCredential)).thenReturn(Optional.of(mockStatusListCredential));
        when(credentialStatusTransactionRepository.save(any(CredentialStatusTransaction.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        CredentialStatusResponse response = credentialStatusService.updateCredentialStatus(request);

        assertNotNull(response);
        assertEquals("revocation", response.getStatusPurpose());
    }

    @Test
    public void updateCredentialStatusV2_InvalidStatusListCredentialFormat_ThrowsException() {
        String statusListCredential = "invalid-format";
        UpdateCredentialStatusRequest request = createValidUpdateCredentialRequest(statusListCredential);

        CertifyException exception = assertThrows(CertifyException.class, () -> {
            credentialStatusService.updateCredentialStatus(request);
        });

        assertEquals("status_list_not_found_for_the_given_id", exception.getErrorCode());
        assertEquals("Status List Credential not found for ID: invalid-format", exception.getMessage());
    }

    private UpdateCredentialStatusRequest createValidUpdateCredentialRequest(String statusListCredential) {
        UpdateCredentialStatusRequest.CredentialStatusDto statusDto = new UpdateCredentialStatusRequest.CredentialStatusDto();
        statusDto.setId(statusListCredential);
        statusDto.setType("BitstringStatusListEntry");
        statusDto.setStatusPurpose("revocation");
        statusDto.setStatusListIndex(87823L);
        statusDto.setStatusListCredential(statusListCredential);

        UpdateCredentialStatusRequest request = new UpdateCredentialStatusRequest();
        request.setCredentialStatus(statusDto);
        request.setStatus(true); // Mark as revoked

        return request;
    }
}