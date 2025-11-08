package taskrepository

import (
	usermodels "gintugas/modules/components/Auth/model"
	projectmodel "gintugas/modules/components/Project/model"
	taskmodel "gintugas/modules/components/Tasks/model"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type TaskRepository interface {
	CreateTask(task *taskmodel.Task) error
	GetTasksByProjectID(projectID uuid.UUID) ([]taskmodel.Task, error)
	GetTaskByID(taskID uuid.UUID) (*taskmodel.Task, error)
	UpdateTask(task *taskmodel.Task) error
	DeleteTask(taskID uuid.UUID) error

	GetTasksByAssigneeID(assigneeID uuid.UUID) ([]taskmodel.Task, error)
	GetTasksByStatus(projectID uuid.UUID, status string) ([]taskmodel.Task, error)
	GetUserByID(userID uuid.UUID) (*usermodels.User, error)
	GetProjectByID(projectID uuid.UUID) (*projectmodel.Project, error)
	IsProjectMember(projectID uuid.UUID, userID uuid.UUID) (bool, error)
}

type taskRepository struct {
	db *gorm.DB
}

func NewTaskRepository(db *gorm.DB) TaskRepository {
	return &taskRepository{
		db: db,
	}
}

func (r *taskRepository) CreateTask(task *taskmodel.Task) error {
	return r.db.Create(task).Error
}

func (r *taskRepository) GetTasksByProjectID(projectID uuid.UUID) ([]taskmodel.Task, error) {
	var tasks []taskmodel.Task
	err := r.db.Where("project_id = ?", projectID).
		Preload("Assignee").
		Find(&tasks).Error
	return tasks, err
}

func (r *taskRepository) GetTaskByID(taskID uuid.UUID) (*taskmodel.Task, error) {
	var task taskmodel.Task
	err := r.db.Where("id = ?", taskID).
		Preload("Assignee").
		First(&task).Error
	if err != nil {
		return nil, err
	}
	return &task, nil
}

func (r *taskRepository) UpdateTask(task *taskmodel.Task) error {
	return r.db.Save(task).Error
}

func (r *taskRepository) DeleteTask(taskID uuid.UUID) error {
	return r.db.Delete(&taskmodel.Task{}, "id = ?", taskID).Error
}

func (r *taskRepository) GetTasksByAssigneeID(assigneeID uuid.UUID) ([]taskmodel.Task, error) {
	var tasks []taskmodel.Task
	err := r.db.Where("assignee_id = ?", assigneeID).
		Preload("Project").
		Preload("Assignee").
		Find(&tasks).Error
	return tasks, err
}

func (r *taskRepository) GetTasksByStatus(projectID uuid.UUID, status string) ([]taskmodel.Task, error) {
	var tasks []taskmodel.Task
	err := r.db.Where("project_id = ? AND status = ?", projectID, status).
		Preload("Assignee").
		Find(&tasks).Error
	return tasks, err
}

func (r *taskRepository) GetUserByID(userID uuid.UUID) (*usermodels.User, error) {
	var user usermodels.User
	err := r.db.First(&user, "id = ?", userID).Error
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (r *taskRepository) GetProjectByID(projectID uuid.UUID) (*projectmodel.Project, error) {
	var project projectmodel.Project
	err := r.db.First(&project, "id = ?", projectID).Error
	if err != nil {
		return nil, err
	}
	return &project, nil
}

func (r *taskRepository) IsProjectMember(projectID uuid.UUID, userID uuid.UUID) (bool, error) {
	var project projectmodel.Project
	err := r.db.First(&project, "id = ?", projectID).Error
	if err != nil {
		return false, err
	}

	//cek user menejer projk
	if project.ManagerID == userID {
		return true, nil
	}

	//cek user dimember projek
	var count int64
	err = r.db.Table("project_members").
		Where("project_id = ? AND user_id = ?", projectID.String(), userID.String()).
		Count(&count).Error

	if err != nil {
		return false, err
	}

	return count > 0, nil
}
