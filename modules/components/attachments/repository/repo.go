package repository

import (
	taskmodel "gintugas/modules/components/Tasks/model"
	attachmentmodel "gintugas/modules/components/attachments/models"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type AttachmentRepository interface {
	CreateAttachment(attachment *attachmentmodel.Attachment) error
	GetAttachmentsByTaskID(taskID uuid.UUID) ([]attachmentmodel.Attachment, error)
	GetAttachmentByID(attachmentID uuid.UUID) (*attachmentmodel.Attachment, error)
	DeleteAttachment(attachmentID uuid.UUID) error
	GetTaskByID(taskID uuid.UUID) (*taskmodel.Task, error)
}

type attachmentRepository struct {
	db *gorm.DB
}

func NewAttachmentRepository(db *gorm.DB) AttachmentRepository {
	return &attachmentRepository{
		db: db,
	}
}

func (r *attachmentRepository) CreateAttachment(attachment *attachmentmodel.Attachment) error {
	return r.db.Create(attachment).Error
}

func (r *attachmentRepository) GetAttachmentsByTaskID(taskID uuid.UUID) ([]attachmentmodel.Attachment, error) {
	var attachments []attachmentmodel.Attachment
	err := r.db.Where("task_id = ?", taskID).
		Preload("Uploader").
		Order("created_at DESC").
		Find(&attachments).Error
	return attachments, err
}

func (r *attachmentRepository) GetAttachmentByID(attachmentID uuid.UUID) (*attachmentmodel.Attachment, error) {
	var attachment attachmentmodel.Attachment
	err := r.db.Where("id = ?", attachmentID).
		Preload("Uploader").
		Preload("Task").
		First(&attachment).Error
	if err != nil {
		return nil, err
	}
	return &attachment, nil
}

func (r *attachmentRepository) DeleteAttachment(attachmentID uuid.UUID) error {
	return r.db.Delete(&attachmentmodel.Attachment{}, "id = ?", attachmentID).Error
}

func (r *attachmentRepository) GetTaskByID(taskID uuid.UUID) (*taskmodel.Task, error) {
	var task taskmodel.Task
	err := r.db.Where("id = ?", taskID).
		Preload("Assignee").
		First(&task).Error
	if err != nil {
		return nil, err
	}
	return &task, nil
}
