package serviceroute

import (
	. "gintugas/modules/components/Tasks/service"
	"net/http"

	"github.com/gin-gonic/gin"
)

type TaskHandler struct {
	taskService TaskService
}

func NewTaskController(taskService TaskService) *TaskHandler {
	return &TaskHandler{
		taskService: taskService,
	}
}

// CreateTask godoc
// @Summary Buat task baru
// @Description Membuat task baru dalam project (hanya admin/manager)
// @Tags tasks
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param project_id path string true "Project ID"
// @Param input body map[string]interface{} true "Data task"
// @Success 201 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Router /api/projects/{project_id}/tasks [post]
func (c *TaskHandler) CreateTask(ctx *gin.Context) {
	task, err := c.taskService.CreateTask(ctx)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	ctx.JSON(http.StatusCreated, gin.H{
		"message": "Task created successfully",
		"task":    task,
	})
}

// GetProjectTasks godoc
// @Summary Get semua tasks dalam project
// @Description Mendapatkan daftar semua tasks dalam project (hanya admin/manager)
// @Tags tasks
// @Produce json
// @Security BearerAuth
// @Param project_id path string true "Project ID"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Router /api/projects/{project_id}/tasks [get]
func (c *TaskHandler) GetProjectTasks(ctx *gin.Context) {
	tasks, err := c.taskService.GetProjectTasks(ctx)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{
		"message": "Tasks retrieved successfully",
		"tasks":   tasks,
	})
}

// GetTaskByID godoc
// @Summary Get task by ID
// @Description Mendapatkan detail task berdasarkan ID (hanya admin/manager)
// @Tags tasks
// @Produce json
// @Security BearerAuth
// @Param project_id path string true "Project ID"
// @Param task_id path string true "Task ID"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Router /api/projects/{project_id}/tasks/{task_id} [get]
func (c *TaskHandler) GetTaskByID(ctx *gin.Context) {
	task, err := c.taskService.GetTaskByID(ctx)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{
		"message": "Task retrieved successfully",
		"task":    task,
	})
}

// UpdateTask godoc
// @Summary Update task
// @Description Update data task (hanya admin/manager)
// @Tags tasks
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param project_id path string true "Project ID"
// @Param task_id path string true "Task ID"
// @Param input body map[string]interface{} true "Data task"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Router /api/projects/{project_id}/tasks/{task_id} [put]
func (c *TaskHandler) UpdateTask(ctx *gin.Context) {
	task, err := c.taskService.UpdateTask(ctx)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{
		"message": "Task updated successfully",
		"task":    task,
	})
}

// DeleteTask godoc
// @Summary Delete task
// @Description Hapus task (hanya admin/manager)
// @Tags tasks
// @Produce json
// @Security BearerAuth
// @Param project_id path string true "Project ID"
// @Param task_id path string true "Task ID"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Router /api/projects/{project_id}/tasks/{task_id} [delete]
func (c *TaskHandler) DeleteTask(ctx *gin.Context) {
	if err := c.taskService.DeleteTask(ctx); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{
		"message": "Task deleted successfully",
	})
}
