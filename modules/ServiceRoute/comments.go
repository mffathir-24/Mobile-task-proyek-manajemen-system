package serviceroute

import (
	. "gintugas/modules/components/command/service"
	"net/http"

	"github.com/gin-gonic/gin"
)

type CommentsHandler struct {
	commentsService CommentsService
}

func NewCommentsHandler(commentsService CommentsService) *CommentsHandler {
	return &CommentsHandler{
		commentsService: commentsService,
	}
}

// CreateComments godoc
// @Summary Buat komentar baru
// @Description Membuat komentar baru pada task (hanya admin/manager/staff)
// @Tags comments
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param task_id path string true "Task ID"
// @Param input body map[string]interface{} true "Data komentar"
// @Success 201 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Router /api/tasks/{task_id}/comments [post]
func (c *CommentsHandler) CreateComments(ctx *gin.Context) {
	comments, err := c.commentsService.CreateComments(ctx)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	ctx.JSON(http.StatusCreated, gin.H{
		"message":  "Comments created successfully",
		"Comments": comments,
	})
}

// GetTasksComments godoc
// @Summary Get semua komentar dalam task
// @Description Mendapatkan daftar semua komentar dalam task (hanya admin/manager/staff)
// @Tags comments
// @Produce json
// @Security BearerAuth
// @Param task_id path string true "Task ID"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Router /api/tasks/{task_id}/comments [get]
func (c *CommentsHandler) GetTasksComments(ctx *gin.Context) {
	comments, err := c.commentsService.GetTasksComments(ctx)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{
		"message":  "Comments retrieved successfully",
		"comments": comments,
	})
}

// GetCommentsByID godoc
// @Summary Get komentar by ID
// @Description Mendapatkan detail komentar berdasarkan ID (hanya admin/manager/staff)
// @Tags comments
// @Produce json
// @Security BearerAuth
// @Param task_id path string true "Task ID"
// @Param comments_id path string true "Comments ID"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Router /api/tasks/{task_id}/comments/{comments_id} [get]
func (c *CommentsHandler) GetCommentsByID(ctx *gin.Context) {
	comments, err := c.commentsService.GetCommentsByID(ctx)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{
		"message":  "Comments retrieved successfully",
		"comments": comments,
	})
}

// UpdateComments godoc
// @Summary Update komentar
// @Description Update data komentar (hanya admin/manager/staff)
// @Tags comments
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param task_id path string true "Task ID"
// @Param comments_id path string true "Comments ID"
// @Param input body map[string]interface{} true "Data komentar"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Router /api/tasks/{task_id}/comments/{comments_id} [put]
func (c *CommentsHandler) UpdateComments(ctx *gin.Context) {
	comments, err := c.commentsService.UpdateComments(ctx)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{
		"message":  "Comments updated successfully",
		"comments": comments,
	})
}

// DeleteComments godoc
// @Summary Delete komentar
// @Description Hapus komentar (hanya admin/manager/staff)
// @Tags comments
// @Produce json
// @Security BearerAuth
// @Param task_id path string true "Task ID"
// @Param comments_id path string true "Comments ID"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Router /api/tasks/{task_id}/comments/{comments_id} [delete]
func (c *CommentsHandler) DeleteComments(ctx *gin.Context) {
	if err := c.commentsService.DeleteComments(ctx); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{
		"message": "Comments deleted successfully",
	})
}
