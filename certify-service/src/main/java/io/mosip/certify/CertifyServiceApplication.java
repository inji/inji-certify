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

package io.mosip.certify;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.context.annotation.Import;
import org.springframework.scheduling.annotation.EnableAsync;

@EnableAsync
@EnableCaching
@Import(io.inji.verify.config.AppConfig.class)
@SpringBootApplication(scanBasePackages = "io.mosip.certify," +
        "io.mosip.kernel.crypto," +
        "io.mosip.kernel.keymanager.hsm," +
        "io.mosip.kernel.cryptomanager," +
        "io.mosip.kernel.keymanagerservice.validator," +
        "io.mosip.kernel.keymanager," +
        "io.mosip.kernel.cryptomanager.util," +
        "io.mosip.kernel.keymanagerservice.helper," +
        "io.mosip.kernel.keymanagerservice.repository," +
        "io.mosip.kernel.keymanagerservice.service," +
        "io.mosip.kernel.keymanagerservice.util," +
        "io.mosip.kernel.keygenerator.bouncycastle," +
        "io.mosip.kernel.signature.service," +
        "io.mosip.kernel.signature.util," +
        "io.mosip.kernel.signature.builder," +
        "io.mosip.kernel.signature.*," +
        "io.mosip.kernel.pdfgenerator.*," +
        "io.mosip.kernel.partnercertservice.service," +
        "io.mosip.kernel.keymanagerservice.repository," +
        "io.mosip.kernel.keymanagerservice.entity," +
        "io.mosip.kernel.partnercertservice.helper," +
        "io.inji.verify.services," +
        "io.inji.verify.key.impl," +
        "io.inji.verify.repository," +
        "io.inji.verify.validator," +
        "${mosip.certify.integration.scan-base-package}")
public class CertifyServiceApplication {
    public static void main(String[] args) {
        SpringApplication.run(CertifyServiceApplication.class, args);
    }
}