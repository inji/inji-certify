package io.mosip.certify.controller;

import io.mosip.certify.core.dto.NonceResponse;
import io.mosip.certify.core.spi.NonceService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
public class NonceController {


    private final NonceService nonceService;

    public NonceController(NonceService nonceService) {
        this.nonceService = nonceService;
    }

    @PostMapping("/nonce")
    public ResponseEntity<NonceResponse> getNonce() {
        NonceResponse nonceResponse = nonceService.generateNonce();
        return ResponseEntity.ok()
                .header("Cache-Control", "no-store")
                .body(nonceResponse);
    }
}
