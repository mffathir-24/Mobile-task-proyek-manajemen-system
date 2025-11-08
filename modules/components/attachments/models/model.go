package models

import (
	usermodels "gintugas/modules/components/Auth/model"
	taskmodel "gintugas/modules/components/Tasks/model"
	"time"

	"github.com/google/uuid"
)

type Attachment struct {
	ID         uuid.UUID `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	TaskID     uuid.UUID `json:"task_id" gorm:"type:uuid;not null"`
	FilePath   string    `json:"file_path" gorm:"type:text;not null"`
	FileName   string    `json:"file_name" gorm:"type:varchar(255);not null"`
	FileSize   int64     `json:"file_size" gorm:"not null"`
	MimeType   string    `json:"mime_type" gorm:"type:varchar(100)"`
	UploadedBy uuid.UUID `json:"uploaded_by" gorm:"type:uuid"`
	CreatedAt  time.Time `json:"created_at" gorm:"default:CURRENT_TIMESTAMP"`

	Task     taskmodel.Task   `json:"task,omitempty" gorm:"foreignKey:TaskID"`
	Uploader *usermodels.User `json:"uploader,omitempty" gorm:"foreignKey:UploadedBy"`
}

type AttachmentRequest struct {
	TaskID uuid.UUID `form:"task_id" binding:"required"`
}

type AttachmentResponse struct {
	ID         uuid.UUID        `json:"id"`
	TaskID     uuid.UUID        `json:"task_id"`
	FilePath   string           `json:"file_path"`
	FileName   string           `json:"file_name"`
	FileSize   int64            `json:"file_size"`
	MimeType   string           `json:"mime_type"`
	UploadedBy uuid.UUID        `json:"uploaded_by"`
	CreatedAt  time.Time        `json:"created_at"`
	Uploader   *usermodels.User `json:"uploader,omitempty"`
}
