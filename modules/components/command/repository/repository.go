package repository

import (
	usermodels "gintugas/modules/components/Auth/model"
	taskmodel "gintugas/modules/components/Tasks/model"
	"gintugas/modules/components/command/model"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type CommentsRepository interface {
	CreateComments(comments *model.Comments) error
	GetCommentsByTaskID(taskID uuid.UUID) ([]model.Comments, error)
	GetCommentsByID(commentsID uuid.UUID) (*model.Comments, error)
	UpdateComments(comments *model.Comments) error
	DeleteComments(commentsID uuid.UUID) error

	GetCommentByUserID(userID uuid.UUID) ([]model.Comments, error)
	GetUserByID(userID uuid.UUID) (*usermodels.User, error)
	GetTaskByID(TaskID uuid.UUID) (*taskmodel.Task, error)
}

type commentsRepository struct {
	db *gorm.DB
}

func NewCommentsRepository(db *gorm.DB) CommentsRepository {
	return &commentsRepository{
		db: db,
	}
}

func (r *commentsRepository) CreateComments(comments *model.Comments) error {
	return r.db.Create(comments).Error
}

func (r *commentsRepository) GetCommentsByTaskID(taskID uuid.UUID) ([]model.Comments, error) {
	var comments []model.Comments
	err := r.db.Where("task_id = ?", taskID).
		Preload("Users").
		Find(&comments).Error
	return comments, err
}

func (r *commentsRepository) GetCommentsByID(commentsID uuid.UUID) (*model.Comments, error) {
	var coment model.Comments
	err := r.db.Where("id = ?", commentsID).
		Preload("Users").
		First(&coment).Error
	if err != nil {
		return nil, err
	}
	return &coment, nil
}

func (r *commentsRepository) UpdateComments(comments *model.Comments) error {
	return r.db.Save(comments).Error
}

func (r *commentsRepository) DeleteComments(commentsID uuid.UUID) error {
	return r.db.Delete(&model.Comments{}, "id = ?", commentsID).Error
}

func (r *commentsRepository) GetCommentByUserID(userID uuid.UUID) ([]model.Comments, error) {
	var coment []model.Comments
	err := r.db.Where("user_id = ?", userID).
		Preload("Tasks").
		Preload("Users").
		Find(&coment).Error
	return coment, err
}

func (r *commentsRepository) GetUserByID(userID uuid.UUID) (*usermodels.User, error) {
	var user usermodels.User
	err := r.db.First(&user, "id = ?", userID).Error
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (r *commentsRepository) GetTaskByID(TaskID uuid.UUID) (*taskmodel.Task, error) {
	var tasks taskmodel.Task
	err := r.db.First(&tasks, "id = ?", TaskID).Error
	if err != nil {
		return nil, err
	}
	return &tasks, nil
}
