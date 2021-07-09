package com.c4_soft.lifix.web;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.util.Date;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.WebFluxTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.http.MediaType;
import org.springframework.http.client.MultipartBodyBuilder;
import org.springframework.http.codec.multipart.FilePart;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.test.web.reactive.server.WebTestClient.RequestHeadersSpec;

import com.c4_soft.lifix.common.storage.StorageService;
import com.c4_soft.lifix.domain.intervention.Fault;
import com.c4_soft.lifix.domain.intervention.FaultAttachment;
import com.c4_soft.lifix.persistence.intervention.FaultAttachmentRepo;
import com.c4_soft.lifix.persistence.intervention.FaultRepo;
import com.c4_soft.lifix.web.dto.FaultEditDto;
import com.c4_soft.springaddons.security.oauth2.test.annotations.IdTokenClaims;
import com.c4_soft.springaddons.security.oauth2.test.annotations.WithMockOidcId;
import com.c4soft.commons.security.WebSecurityConfig;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@WebFluxTest
@Import(WebSecurityConfig.class)
class FaultControllerTest {

    @MockBean
    private StorageService storageService;

    @MockBean
    private FaultRepo faultRepo;

    @MockBean
    private FaultAttachmentRepo attachmentRepo;

    @Autowired
    private WebTestClient client;

    @Captor
    ArgumentCaptor<Fault> faultCaptor;

    @BeforeEach
    public void setUp() {
        final var fault42 = fault42();
        final var fault51 = fault51();
        final var faultClosed = faultClosed();
        final var attachment42_1 = attachment42_1();
        final var attachment42_2 = attachment42_2();

        when(faultRepo.save(any(Fault.class))).thenAnswer(invocation -> {
            final var saved = (Fault) invocation.getArgument(0);
            if (saved.getId() == null) {
                saved.setId(66L);
            }
            return Mono.just(saved);
        });
        when(faultRepo.findById(fault42.getId())).thenReturn(Mono.just(fault42));
        when(faultRepo.findById(fault51.getId())).thenReturn(Mono.just(fault51));
        when(faultRepo.findById(faultClosed.getId())).thenReturn(Mono.just(faultClosed));
        when(faultRepo.findOpened()).thenReturn(Flux.fromArray(new Fault[] { fault42, fault51 }));
        when(faultRepo.findAll()).thenReturn(Flux.fromArray(new Fault[] { faultClosed, fault42, fault51 }));
        when(faultRepo.deleteById(anyLong())).thenReturn(Mono.just(42).then());

        when(attachmentRepo.save(any(FaultAttachment.class))).thenAnswer(invocation -> {
            final var saved = (FaultAttachment) invocation.getArgument(0);
            if (saved.getId() == null) {
                saved.setId(666L);
            }
            return Mono.just(saved);
        });
        when(attachmentRepo.findByFaultId(fault42.getId())).thenReturn(Flux.fromArray(new FaultAttachment[] { attachment42_1, attachment42_2 }));
        when(attachmentRepo.findByFaultId(fault51.getId())).thenReturn(Flux.empty());
        when(attachmentRepo.findByFaultId(faultClosed.getId())).thenReturn(Flux.empty());
        when(attachmentRepo.findById(attachment42_1.getId())).thenReturn(Mono.just(attachment42_1));
        when(attachmentRepo.findById(attachment42_2.getId())).thenReturn(Mono.just(attachment42_2));
        when(attachmentRepo.deleteById(anyLong())).thenReturn(Mono.empty().then());

        when(storageService.store(any(FilePart.class), anyString())).thenReturn(Mono.empty().then());
        when(storageService.loadAsResource(anyString())).thenReturn(new ClassPathResource("tonton-pirate.jpg"));
        when(storageService.delete(anyString())).thenReturn(true);
    }

    /*----------------*/
    /* Access control */
    /*----------------*/

    //Create
    @Test
    void whenUserIsNotAuthenticatedThenCreateReturns401() {
        faultCreationRequest("test").exchange().expectStatus().isUnauthorized();
    }

    //Retrieve
    @Test
    @WithMockOidcId
    void whenUserIsAuthenticatedWithoutFaultEditorThenCreateReturns403() {
        faultCreationRequest("test").exchange().expectStatus().isForbidden();
    }

    @Test
    void whenUserIsNotAuthenticatedThenRetrieveManyReturns401() {
        faultRetrieveManyRequest(false).exchange().expectStatus().isUnauthorized();
    }

    @Test
    void whenUserIsNotAuthenticatedThenRetrieveByIdReturns401() {
        final var fault = fault42();
        faultRetrieveByIdRequest(fault.getId()).exchange().expectStatus().isUnauthorized();
    }

    //Update
    @Test
    void whenUserIsNotAuthenticatedThenUpdateReturns401() {
        final var fault = fault42();
        faultUpdateRequest(fault.getId(), "test", false).exchange().expectStatus().isUnauthorized();
    }

    @Test
    @WithMockOidcId
    void whenUserIsAuthenticatedWithoutFaultEditorThenUpdateReturns403() {
        final var fault = fault42();
        faultUpdateRequest(fault.getId(), "test", false).exchange().expectStatus().isForbidden();
    }

    //Delete
    @Test
    void whenUserIsNotAuthenticatedThenDeleteReturns401() {
        final var fault = fault42();
        faultDeleteRequest(fault.getId()).exchange().expectStatus().isUnauthorized();
    }

    @Test
    @WithMockOidcId
    void whenUserIsAuthenticatedWithoutFaultEditorThenDeleteReturns403() {
        final var fault = fault42();
        faultDeleteRequest(fault.getId()).exchange().expectStatus().isForbidden();
    }

    //Add attachment
    @Test
    void whenUserIsNotAuthenticatedThenCreateAttachmentReturns401() throws IOException {
        final var fault = fault42();
        attachmentCreationRequest(fault.getId(), new ClassPathResource("tonton-pirate.jpg")).exchange().expectStatus().isUnauthorized();
    }

    @Test
    @WithMockOidcId
    void whenUserIsAuthenticatedWithoutFaultEditorThenCreateAttachmentReturns403() throws IOException {
        final var fault = fault42();
        attachmentCreationRequest(fault.getId(), new ClassPathResource("tonton-pirate.jpg")).exchange().expectStatus().isForbidden();
    }

    //Retrieve attachments
    @Test
    void whenUserIsNotAuthenticatedThenRetrieveAttachmentByIdReturns401() throws IOException {
        final var attachment = attachment42_2();
        attachmentRetrieveByIdRequest(attachment).exchange().expectStatus().isUnauthorized();
    }

    //Remove attachment
    @Test
    void whenUserIsNotAuthenticatedThenDeleteAttachmentByIdReturns401() throws IOException {
        final var attachment = attachment42_2();
        attachmentDeleteRequest(attachment).exchange().expectStatus().isUnauthorized();
    }

    @Test
    @WithMockOidcId
    void whenUserIsAuthenticatedWithoutFaultEditorThenDeleteAttachmentByIdReturns403() throws IOException {
        final var attachment = attachment42_2();
        attachmentDeleteRequest(attachment).exchange().expectStatus().isForbidden();
    }

    /*--------------*/
    /* Nominal path */
    /*--------------*/

    //Create
    @Test
    @WithMockOidcId("FAULT_EDITOR")
    void whenFaultEditorProvidesWithDescriptionThenCreateReturns201() {
        faultCreationRequest("test").exchange().expectStatus().isCreated();
    }

    //Retrieve
    @Test
    @WithMockOidcId
    void whenUserIsAuthenticatedThenRetrieveManyReturns200() {
        faultRetrieveManyRequest(false).exchange().expectStatus().isOk();

        faultRetrieveManyRequest(true).exchange().expectStatus().isOk();
    }

    @Test
    @WithMockOidcId
    void whenUserProvidesWithValidFaultIdThenRetrieveByIdReturns200() {
        final var fault = fault42();
        faultRetrieveByIdRequest(fault.getId()).exchange().expectStatus().isOk();
    }

    //Update
    @Test
    @WithMockOidcId("FAULT_EDITOR")
    void whenFaultEditorPutsOpenedFaultUpdateDtoAtOpenedFaultIdThenUpdateSavesDescriptionAndReturns202() {
        final var fault = fault42();
        faultUpdateRequest(fault.getId(), "test", false).exchange().expectStatus().isAccepted();

        verify(faultRepo).save(faultCaptor.capture());
        assertEquals("test", faultCaptor.getValue().getDescription());
        assertNull(faultCaptor.getValue().getClosedBy());
        assertNull(faultCaptor.getValue().getClosedAt());
    }

    @Test
    @WithMockOidcId(authorities = "FAULT_EDITOR", id = @IdTokenClaims(sub = "subManager3"))
    void whenFaultEditorPutsFaultClosedUpdateDtoAtOpendedFaultIdThenUpdateSavesDescriptionAndClosesAndReturns202() {
        final var fault = fault42();
        faultUpdateRequest(fault.getId(), "test", true).exchange().expectStatus().isAccepted();

        verify(faultRepo).save(faultCaptor.capture());
        assertEquals("test", faultCaptor.getValue().getDescription());
        assertEquals("subManager3", faultCaptor.getValue().getClosedBy());
        assertNotNull(faultCaptor.getValue().getClosedAt());
    }

    @Test
    @WithMockOidcId(authorities = "FAULT_EDITOR", id = @IdTokenClaims(sub = "subManager3"))
    void whenFaultEditorPutsOpenedFaultUpdateDtoAtOpenedFaultIdThenUpdateSavesDescriptionAndRemovesClosedAndReturns202() {
        final var fault = faultClosed();
        faultUpdateRequest(fault.getId(), "test", false).exchange().expectStatus().isAccepted();

        verify(faultRepo).save(faultCaptor.capture());
        assertEquals("test", faultCaptor.getValue().getDescription());
        assertNull(faultCaptor.getValue().getClosedBy());
        assertNull(faultCaptor.getValue().getClosedAt());
    }

    @Test
    @WithMockOidcId(authorities = "FAULT_EDITOR", id = @IdTokenClaims(sub = "subManager3"))
    void whenFaultEditorPutsClosedFaultUpdateDtoAtClosedFaultIdThenUpdateSavesDescriptionAndDoesNotChangeClosedAndReturns202() {
        final var fault = faultClosed();
        faultUpdateRequest(fault.getId(), "test", true).exchange().expectStatus().isAccepted();

        verify(faultRepo).save(faultCaptor.capture());
        assertEquals("test", faultCaptor.getValue().getDescription());
        assertEquals("subManager2", faultCaptor.getValue().getClosedBy());
        assertNotNull(faultCaptor.getValue().getClosedAt());
    }

    //Delete
    @Test
    @WithMockOidcId("FAULT_EDITOR")
    void whenFaultEditorDeletesExistingFaultThenDeleteReturns202() {
        final var fault = fault42();
        faultDeleteRequest(fault.getId()).exchange().expectStatus().isAccepted();
    }

    //Add attachment
    @Test
    @WithMockOidcId("FAULT_EDITOR")
    void whenFaultEditorAddsImageToExistingFaultThenCreateAttachmentReturns201() throws IOException {
        final var fault = fault42();
        attachmentCreationRequest(fault.getId(), new ClassPathResource("tonton-pirate.jpg")).exchange().expectStatus().isCreated();
    }

    //Retrieve attachments
    @Test
    @WithMockOidcId
    void whenUserProvidesAssociatedFaultAndAttachmentIdsThenRetrieveAttachmentByIdReturns200() throws IOException {
        final var attachment = attachment42_2();
        attachmentRetrieveByIdRequest(attachment).exchange().expectStatus().isOk();
    }

    //Remove attachment
    @Test
    @WithMockOidcId("FAULT_EDITOR")
    void whenFaultEditorThenDeleteAttachmentByIdReturns202() throws IOException {
        final var attachment = attachment42_2();
        attachmentDeleteRequest(attachment).exchange().expectStatus().isAccepted();
    }

    /*-----------------*/
    /* Errors handling */
    /*-----------------*/

    /*---------*/
    /* Helpers */
    /*---------*/

    RequestHeadersSpec<?> faultCreationRequest(String descrption) {
        return client.post().uri("https://localhost:443/faults").contentType(MediaType.APPLICATION_JSON).bodyValue(new FaultEditDto(descrption, false));
    }

    RequestHeadersSpec<?> faultRetrieveManyRequest(boolean isClosedIncluded) {
        final var req = client.get().uri("https://localhost:443/faults").accept(MediaType.APPLICATION_JSON);
        if (isClosedIncluded) {
            req.attribute("isClosedIncluded", true);
        }
        return req;
    }

    RequestHeadersSpec<?> faultRetrieveByIdRequest(long faultId) {
        return client.get().uri("https://localhost:443/faults/" + faultId).accept(MediaType.APPLICATION_JSON);
    }

    RequestHeadersSpec<?> faultUpdateRequest(long faultId, String descrption, boolean isClosed) {
        return client.put()
                .uri("https://localhost:443/faults/" + faultId)
                .accept(MediaType.APPLICATION_JSON)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(new FaultEditDto(descrption, isClosed));
    }

    RequestHeadersSpec<?> faultDeleteRequest(long faultId) {
        return client.delete().uri("https://localhost:443/faults/" + faultId).accept(MediaType.APPLICATION_JSON);
    }

    RequestHeadersSpec<?> attachmentCreationRequest(long faultId, Resource resource) throws IOException {
        final var bodyBuilder = new MultipartBodyBuilder();
        bodyBuilder.part("attachment", resource);
        return client.post()
                .uri("https://localhost:443/faults/" + faultId + "/attachments")
                .contentType(MediaType.MULTIPART_FORM_DATA)
                .bodyValue(bodyBuilder.build());
    }

    RequestHeadersSpec<?> attachmentRetrieveByIdRequest(FaultAttachment attachment) {
        return client.get()
                .uri("https://localhost:443/faults/" + attachment.getFaultId() + "/attachments/" + attachment.getId() + "." + attachment.getExtension());
    }

    RequestHeadersSpec<?> attachmentDeleteRequest(FaultAttachment attachment) {
        return client.delete()
                .uri("https://localhost:443/faults/" + attachment.getFaultId() + "/attachments/" + attachment.getId() + "." + attachment.getExtension());
    }

    /* Fixtures */

    static Fault fault42() {
        return new Fault(42L, "Fault n°42", "subManager1", new Date(1627089125032L), null, null);
    }

    static Fault fault51() {
        return new Fault(51L, "Fault n°51", "subManager1", new Date(1627089126032L), null, null);
    }

    static Fault faultClosed() {
        return new Fault(6L, "Fault n°6", "subManager1", new Date(1627089124032L), "subManager2", new Date(1627089127032L));
    }

    static FaultAttachment attachment42_1() {
        final var faultId = fault42().getId();
        return new FaultAttachment(Long.parseLong(faultId + "1"), faultId, "jpg");
    }

    static FaultAttachment attachment42_2() {
        final var faultId = fault42().getId();
        return new FaultAttachment(Long.parseLong(faultId + "2"), faultId, "jpg");
    }

}
