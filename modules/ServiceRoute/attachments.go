package serviceroute

import (
	attachmentservice "gintugas/modules/components/attachments/service"
	"net/http"

	"github.com/gin-gonic/gin"
)

type AttachmentHandler struct {
	attachmentService attachmentservice.AttachmentService
}

func NewAttachmentHandler(attachmentService attachmentservice.AttachmentService) *AttachmentHandler {
	return &AttachmentHandler{
		attachmentService: attachmentService,
	}
}

// UploadAttachment godoc
// @Summary Upload file attachment
// @Description Mengupload file attachment untuk task (hanya admin/manager/staff)
// @Tags attachments
// @Accept multipart/form-data
// @Produce json
// @Security BearerAuth
// @Param task_id path string true "Task ID"
// @Param file formData file true "File attachment"
// @Success 201 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Router /api/tasks/{task_id}/attachments [post]
func (h *AttachmentHandler) UploadAttachment(ctx *gin.Context) {
	response, err := h.attachmentService.UploadAttachment(ctx)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	ctx.JSON(http.StatusCreated, gin.H{
		"message": "File berhasil diupload",
		"data":    response,
	})
}

// GetTaskAttachments godoc
// @Summary Get semua attachments dalam task
// @Description Mendapatkan daftar semua attachments dalam task (hanya admin/manager/staff)
// @Tags attachments
// @Produce json
// @Security BearerAuth
// @Param task_id path string true "Task ID"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Router /api/tasks/{task_id}/attachments [get]
func (h *AttachmentHandler) GetTaskAttachments(ctx *gin.Context) {
	attachments, err := h.attachmentService.GetTaskAttachments(ctx)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{
		"message": "Berhasil mengambil attachments",
		"data":    attachments,
	})
}

// DeleteAttachment godoc
// @Summary Delete attachment
// @Description Hapus attachment (hanya admin/manager/staff)
// @Tags attachments
// @Produce json
// @Security BearerAuth
// @Param attachment_id path string true "Attachment ID"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Router /api/attachments/{attachment_id} [delete]
func (h *AttachmentHandler) DeleteAttachment(ctx *gin.Context) {
	if err := h.attachmentService.DeleteAttachment(ctx); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{
		"message": "Attachment berhasil dihapus",
	})
}

// DownloadAttachment godoc
// @Summary Download attachment
// @Description Download file attachment
// @Tags attachments
// @Produce octet-stream
// @Security BearerAuth
// @Param attachment_id path string true "Attachment ID"
// @Success 200 {file} binary
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Router /api/attachments/{attachment_id}/download [get]
func (h *AttachmentHandler) DownloadAttachment(ctx *gin.Context) {
	filePath, err := h.attachmentService.DownloadAttachment(ctx)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	ctx.File(filePath)
}
