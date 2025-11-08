package taskservice

import (
	"errors"
	"fmt"
	. "gintugas/modules/components/Mail/service"
	taskmodel "gintugas/modules/components/Tasks/model"
	taskrepository "gintugas/modules/components/Tasks/repository"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type TaskService interface {
	CreateTask(ctx *gin.Context) (*taskmodel.TaskResponse, error)
	GetProjectTasks(ctx *gin.Context) ([]taskmodel.TaskResponse, error)
	GetTaskByID(ctx *gin.Context) (*taskmodel.TaskResponse, error)
	UpdateTask(ctx *gin.Context) (*taskmodel.TaskResponse, error)
	DeleteTask(ctx *gin.Context) error
}

type taskService struct {
	taskRepo    taskrepository.TaskRepository
	mailService MailService
}

func NewTaskService(taskRepo taskrepository.TaskRepository, mailService MailService) TaskService {
	return &taskService{
		taskRepo:    taskRepo,
		mailService: mailService,
	}
}

func (s *taskService) validateProjectManager(ctx *gin.Context, projectID uuid.UUID) error {
	userID, exists := ctx.Get("user_id")
	if !exists {
		return errors.New("unauthorized: user tidak terautentikasi")
	}

	userIDStr, ok := userID.(string)
	if !ok {
		return errors.New("invalid user id format")
	}

	userUUID, err := uuid.Parse(userIDStr)
	if err != nil {
		return errors.New("invalid user id format: " + err.Error())
	}

	//cek user menejer dari proyek
	project, err := s.taskRepo.GetProjectByID(projectID)
	if err != nil {
		return fmt.Errorf("gagal mengambil detail project: %v", err)
	}

	if project.ManagerID != userUUID {
		return errors.New("forbidden: hanya manager project yang bisa melakukan operasi ini")
	}

	return nil
}

// user member dari projek
func (s *taskService) validateProjectMember(projectID uuid.UUID, assigneeID uuid.UUID) error {
	isMember, err := s.taskRepo.IsProjectMember(projectID, assigneeID)
	if err != nil {
		return fmt.Errorf("gagal memeriksa member project: %v", err)
	}

	if !isMember {
		return errors.New("assignee harus menjadi member dari project ini")
	}

	return nil
}

func (s *taskService) CreateTask(ctx *gin.Context) (*taskmodel.TaskResponse, error) {
	projectID := ctx.Param("project_id")
	projectUUID, err := uuid.Parse(projectID)
	if err != nil {
		return nil, errors.New("Gagal format Project ID")
	}
	//cek menejer projek
	if err := s.validateProjectManager(ctx, projectUUID); err != nil {
		return nil, err
	}

	var taskReq taskmodel.TaskRequest
	if err := ctx.ShouldBindJSON(&taskReq); err != nil {
		return nil, err
	}
	//cek member dari projek
	if taskReq.AssigneeID != nil {
		if err := s.validateProjectMember(projectUUID, *taskReq.AssigneeID); err != nil {
			return nil, err
		}
	}

	task := &taskmodel.Task{
		ProjectID:   projectUUID,
		Title:       taskReq.Title,
		Description: taskReq.Description,
		Status:      taskReq.Status,
		AssigneeID:  taskReq.AssigneeID,
		DueDate:     taskReq.DueDate,
	}

	if task.Status == "" {
		task.Status = "todo"
	}

	if err := s.taskRepo.CreateTask(task); err != nil {
		return nil, err
	}

	if task.AssigneeID != nil {
		assignee, err := s.taskRepo.GetUserByID(*task.AssigneeID)
		if err != nil {
			return nil, fmt.Errorf("Gagal mengambil detail assignee: %v", err)
		}

		project, err := s.taskRepo.GetProjectByID(task.ProjectID)
		if err != nil {
			return nil, fmt.Errorf("Gagal mengampil detail projek: %v", err)
		}

		err = s.mailService.SendTaskAssignmentNotification(
			assignee.Email,
			task.Title,
			project.Nama,
		)
		if err != nil {

			fmt.Printf("gagal untuk mengirim email notifikasi: %v\n", err)
		}
	}

	return s.convertToResponse(task), nil

}

func (s *taskService) GetProjectTasks(ctx *gin.Context) ([]taskmodel.TaskResponse, error) {
	projectID := ctx.Param("project_id")
	projectUUID, err := uuid.Parse(projectID)
	if err != nil {
		return nil, errors.New("Gagal format Project ID")
	}

	tasks, err := s.taskRepo.GetTasksByProjectID(projectUUID)
	if err != nil {
		return nil, err
	}

	var response []taskmodel.TaskResponse
	for _, task := range tasks {
		response = append(response, *s.convertToResponse(&task))
	}

	return response, nil
}

func (s *taskService) GetTaskByID(ctx *gin.Context) (*taskmodel.TaskResponse, error) {
	taskID := ctx.Param("task_id")
	taskUUID, err := uuid.Parse(taskID)
	if err != nil {
		return nil, errors.New("Gagal format task ID")
	}

	task, err := s.taskRepo.GetTaskByID(taskUUID)
	if err != nil {
		return nil, err
	}

	return s.convertToResponse(task), nil
}

func (s *taskService) UpdateTask(ctx *gin.Context) (*taskmodel.TaskResponse, error) {
	taskID := ctx.Param("task_id")
	taskUUID, err := uuid.Parse(taskID)
	if err != nil {
		return nil, errors.New("Gagal format task ID")
	}

	existingTask, err := s.taskRepo.GetTaskByID(taskUUID)
	if err != nil {
		return nil, err
	}

	if err := s.validateProjectManager(ctx, existingTask.ProjectID); err != nil {
		return nil, err
	}

	var taskReq taskmodel.TaskRequest
	if err := ctx.ShouldBindJSON(&taskReq); err != nil {
		return nil, err
	}

	if taskReq.AssigneeID != nil {
		if err := s.validateProjectMember(existingTask.ProjectID, *taskReq.AssigneeID); err != nil {
			return nil, err
		}
	}

	if taskReq.Title != "" {
		existingTask.Title = taskReq.Title
	}
	if taskReq.Description != "" {
		existingTask.Description = taskReq.Description
	}
	if taskReq.Status != "" {
		existingTask.Status = taskReq.Status
	}
	if taskReq.AssigneeID != nil {
		existingTask.AssigneeID = taskReq.AssigneeID
	}

	if taskReq.DueDate != nil && !taskReq.DueDate.IsZero() {
		existingTask.DueDate = taskReq.DueDate
	}

	existingTask.UpdatedAt = time.Now()

	if err := s.taskRepo.UpdateTask(existingTask); err != nil {
		return nil, err
	}

	if existingTask.AssigneeID != nil {
		assignee, err := s.taskRepo.GetUserByID(*existingTask.AssigneeID)
		if err != nil {
			return nil, fmt.Errorf("Gagal mengambil detail assignee: %v", err)
		}

		project, err := s.taskRepo.GetProjectByID(existingTask.ProjectID)
		if err != nil {
			return nil, fmt.Errorf("Gagal mengambil detail projek: %v", err)
		}

		err = s.mailService.SendTaskAssignmentNotification(
			assignee.Email,
			existingTask.Title,
			project.Nama,
		)

		if err != nil {
			fmt.Printf("Gagal untuk mengirim notif: %v\n", err)
		}
	}

	return s.convertToResponse(existingTask), nil
}

func (s *taskService) DeleteTask(ctx *gin.Context) error {
	taskID := ctx.Param("task_id")
	taskUUID, err := uuid.Parse(taskID)
	if err != nil {
		return errors.New("Gagal format task ID")
	}

	task, err := s.taskRepo.GetTaskByID(taskUUID)
	if err != nil {
		return err
	}

	if err := s.validateProjectManager(ctx, task.ProjectID); err != nil {
		return err
	}

	return s.taskRepo.DeleteTask(taskUUID)
}

func (s *taskService) convertToResponse(task *taskmodel.Task) *taskmodel.TaskResponse {
	return &taskmodel.TaskResponse{
		ID:          task.ID,
		ProjectID:   task.ProjectID,
		Title:       task.Title,
		Description: task.Description,
		Status:      task.Status,
		AssigneeID:  task.AssigneeID,
		DueDate:     task.DueDate,
		CreatedAt:   task.CreatedAt,
		UpdatedAt:   task.UpdatedAt,
		Assignee:    task.Assignee,
	}
}
