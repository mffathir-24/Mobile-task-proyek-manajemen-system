package taskmodel

import (
	usermodels "gintugas/modules/components/Auth/model"
	projectmodel "gintugas/modules/components/Project/model"
	"time"

	"github.com/google/uuid"
)

type Task struct {
	ID          uuid.UUID  `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	ProjectID   uuid.UUID  `json:"project_id" gorm:"type:uuid;not null"`
	Title       string     `json:"title" gorm:"type:varchar(200);not null"`
	Description string     `json:"description" gorm:"type:text"`
	Status      string     `json:"status" gorm:"type:task_status;default:'todo'"`
	AssigneeID  *uuid.UUID `json:"assignee_id" gorm:"type:uuid"`
	DueDate     *time.Time `json:"due_date" gorm:"type:date"`
	CreatedAt   time.Time  `json:"created_at" gorm:"default:CURRENT_TIMESTAMP"`
	UpdatedAt   time.Time  `json:"updated_at" gorm:"default:CURRENT_TIMESTAMP"`

	Project  projectmodel.Project `json:"project,omitempty" gorm:"foreignKey:ProjectID"`
	Assignee *usermodels.User     `json:"assignee,omitempty" gorm:"foreignKey:AssigneeID"`
}

type TaskRequest struct {
	Title       string     `json:"title" binding:"required"`
	Description string     `json:"description"`
	Status      string     `json:"status" binding:"omitempty,oneof=todo in-progress done"`
	AssigneeID  *uuid.UUID `json:"assignee_id"`
	DueDate     *time.Time `json:"due_date"`
}

type TaskResponse struct {
	ID          uuid.UUID        `json:"id"`
	ProjectID   uuid.UUID        `json:"project_id"`
	Title       string           `json:"title"`
	Description string           `json:"description"`
	Status      string           `json:"status"`
	AssigneeID  *uuid.UUID       `json:"assignee_id"`
	DueDate     *time.Time       `json:"due_date"`
	CreatedAt   time.Time        `json:"created_at"`
	UpdatedAt   time.Time        `json:"updated_at"`
	Assignee    *usermodels.User `json:"assignee,omitempty"`
}
