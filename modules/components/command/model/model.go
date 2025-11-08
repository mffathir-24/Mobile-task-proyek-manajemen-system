package model

import (
	usermodels "gintugas/modules/components/Auth/model"
	taskmodel "gintugas/modules/components/Tasks/model"
	"time"

	"github.com/google/uuid"
)

type Comments struct {
	ID        uuid.UUID  `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	TaskID    uuid.UUID  `json:"task_id" gorm:"type:uuid;not null"`
	UserID    *uuid.UUID `json:"user_id" gorm:"type:uuid"`
	Content   string     `json:"content" gorm:"type:text;not null"`
	CreatedAt time.Time  `json:"created_at" gorm:"default:CURRENT_TIMESTAMP"`
	UpdatedAt time.Time  `json:"updated_at" gorm:"default:CURRENT_TIMESTAMP"`

	Tasks taskmodel.Task   `json:"tasks,omitempty" gorm:"foreignKey:TaskID"`
	Users *usermodels.User `json:"users,omitempty" gorm:"foreignKey:UserID"`
}

type CommentsRequest struct {
	Content string `json:"content" binding:"required"`
}

type CommentsResponse struct {
	ID        uuid.UUID        `json:"id"`
	TaskID    uuid.UUID        `json:"task_id"`
	Content   string           `json:"content"`
	UserID    *uuid.UUID       `json:"user_id"`
	CreatedAt time.Time        `json:"created_at"`
	UpdatedAt time.Time        `json:"updated_at"`
	Users     *usermodels.User `json:"users,omitempty"`
}
