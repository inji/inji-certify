package io.mosip.certify.services;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;

import io.mosip.certify.core.dto.RenderingTemplateDTO;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.exception.RenderingTemplateException;
import io.mosip.certify.entity.RenderingTemplate;
import io.mosip.certify.repository.RenderingTemplateRepository;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RunWith(MockitoJUnitRunner.class)
public class RenderingTemplateServiceImplTest {
    @InjectMocks
    RenderingTemplateServiceImpl renderingTemplateService;

    @Mock
    RenderingTemplateRepository svgRenderTemplateRepository;

    @Test
    public void getSvgTemplate_withValidDetail_thenPass() {
        RenderingTemplate svgRenderTemplate = new RenderingTemplate();
        svgRenderTemplate.setId("fake-id");
        String svgTemplate = """
                    <svg xmlns=\\"http://www.w3.org/2000/svg\\" width=\\"200\\" height=\\"200\\">
                    <rect width=\\"200\\" height=\\"200\\" fill=\\"#ff6347\\"/>
                    <text x=\\"100\\" y=\\"100\\" font-size=\\"30\\" text-anchor=\\"middle\\" fill=\\"white\\">
                    Hello, SVG!
                    </text></svg>
                """;
        svgRenderTemplate.setTemplate(svgTemplate);
        svgRenderTemplate.setCreatedtimes(LocalDateTime.now());
        Optional<RenderingTemplate> optional = Optional.of(svgRenderTemplate);
        Mockito.when(svgRenderTemplateRepository.findById(Mockito.any())).thenReturn(optional);
        RenderingTemplateDTO svgRenderTemplateResponse = renderingTemplateService.getTemplate("fake-id");
        Assert.assertNotNull(svgRenderTemplateResponse);
        Assert.assertEquals(svgRenderTemplate.getId(), svgRenderTemplateResponse.getId());
        Assert.assertEquals(svgTemplate, optional.get().getTemplate());
    }

    @Test
    public void getSvgTemplate_withInvalidId_thenFail() {
        Mockito.when(svgRenderTemplateRepository.findById(Mockito.any())).thenReturn(Optional.empty());
        RenderingTemplateException templateException = Assert.assertThrows(RenderingTemplateException.class, () -> {
            renderingTemplateService.getTemplate("fake-id");
        });
        Assert.assertEquals(ErrorConstants.INVALID_TEMPLATE_ID, templateException.getErrorCode());
    }

    @Test
    public void getAllTemplates_withValidCredentialConfigKeyId_returnsAllTemplates() {
        RenderingTemplate template1 = new RenderingTemplate();
        template1.setId("tmpl-en-front");
        template1.setTemplate("<svg>front-en</svg>");
        template1.setLanguage("en");
        template1.setSide("front");
        template1.setCredentialConfigKeyId("FarmerCredential_VCDM2.0");
        template1.setCreatedtimes(LocalDateTime.now());

        RenderingTemplate template2 = new RenderingTemplate();
        template2.setId("tmpl-en-back");
        template2.setTemplate("<svg>back-en</svg>");
        template2.setLanguage("en");
        template2.setSide("back");
        template2.setCredentialConfigKeyId("FarmerCredential_VCDM2.0");
        template2.setCreatedtimes(LocalDateTime.now());

        RenderingTemplate template3 = new RenderingTemplate();
        template3.setId("tmpl-hi-front");
        template3.setTemplate("<svg>front-hi</svg>");
        template3.setLanguage("hi");
        template3.setSide("front");
        template3.setCredentialConfigKeyId("FarmerCredential_VCDM2.0");
        template3.setCreatedtimes(LocalDateTime.now());

        Mockito.when(svgRenderTemplateRepository.findByCredentialConfigKeyId("FarmerCredential_VCDM2.0"))
                .thenReturn(List.of(template1, template2, template3));

        List<RenderingTemplateDTO> result = renderingTemplateService.getAllTemplates("FarmerCredential_VCDM2.0");

        Assert.assertNotNull(result);
        Assert.assertEquals(3, result.size());
        Assert.assertEquals("tmpl-en-front", result.get(0).getId());
        Assert.assertEquals("en", result.get(0).getLanguage());
        Assert.assertEquals("front", result.get(0).getSide());
        Assert.assertEquals("tmpl-en-back", result.get(1).getId());
        Assert.assertEquals("tmpl-hi-front", result.get(2).getId());
    }

    @Test
    public void getAllTemplates_withNoMatchingKey_returnsEmptyList() {
        Mockito.when(svgRenderTemplateRepository.findByCredentialConfigKeyId("unknown-key"))
                .thenReturn(List.of());

        List<RenderingTemplateDTO> result = renderingTemplateService.getAllTemplates("unknown-key");

        Assert.assertNotNull(result);
        Assert.assertTrue(result.isEmpty());
    }

}
