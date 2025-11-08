package service

import (
	"errors"
	"gintugas/modules/components/command/model"
	"gintugas/modules/components/command/repository"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type CommentsService interface {
	CreateComments(ctx *gin.Context) (*model.CommentsResponse, error)
	GetTasksComments(ctx *gin.Context) ([]model.CommentsResponse, error)
	GetCommentsByID(ctx *gin.Context) (*model.CommentsResponse, error)
	UpdateComments(ctx *gin.Context) (*model.CommentsResponse, error)
	DeleteComments(ctx *gin.Context) error
}

type commentsService struct {
	commentsRepo repository.CommentsRepository
}

func NewTaskService(commentsRepo repository.CommentsRepository) CommentsService {
	return &commentsService{
		commentsRepo: commentsRepo,
	}
}

func (s *commentsService) CreateComments(ctx *gin.Context) (*model.CommentsResponse, error) {
	taskID := ctx.Param("task_id")
	taskUUID, err := uuid.Parse(taskID)
	if err != nil {
		return nil, errors.New("Gagal format Taks ID")
	}

	uid, exists := ctx.Get("user_id")
	if !exists {
		return &model.CommentsResponse{}, errors.New("unauthorized: user tidak terautentikasi")
	}

	userIDStr, ok := uid.(string)
	if !ok {
		return &model.CommentsResponse{}, errors.New("invalid user id format")
	}

	userUUID, err := uuid.Parse(userIDStr)
	if err != nil {
		return &model.CommentsResponse{}, errors.New("invalid user id format: " + err.Error())
	}

	var commentsreq model.CommentsRequest
	if err := ctx.ShouldBindJSON(&commentsreq); err != nil {
		return nil, err
	}

	comments := &model.Comments{
		TaskID:  taskUUID,
		UserID:  &userUUID,
		Content: commentsreq.Content,
	}

	if err := s.commentsRepo.CreateComments(comments); err != nil {
		return nil, err
	}

	return s.convertToResponse(comments), nil

}

func (s *commentsService) GetTasksComments(ctx *gin.Context) ([]model.CommentsResponse, error) {
	taskID := ctx.Param("task_id")
	taskUUID, err := uuid.Parse(taskID)
	if err != nil {
		return nil, errors.New("Gagal format Project ID")
	}

	comments, err := s.commentsRepo.GetCommentsByTaskID(taskUUID)
	if err != nil {
		return nil, err
	}

	var response []model.CommentsResponse
	for _, komen := range comments {
		response = append(response, *s.convertToResponse(&komen))
	}

	return response, nil
}

func (s *commentsService) GetCommentsByID(ctx *gin.Context) (*model.CommentsResponse, error) {
	commentsID := ctx.Param("comments_id")
	commentsUUID, err := uuid.Parse(commentsID)
	if err != nil {
		return nil, errors.New("Gagal format task ID")
	}

	komen, err := s.commentsRepo.GetCommentsByID(commentsUUID)
	if err != nil {
		return nil, err
	}

	return s.convertToResponse(komen), nil
}

func (s *commentsService) UpdateComments(ctx *gin.Context) (*model.CommentsResponse, error) {
	commentsID := ctx.Param("comments_id")
	commentsUUID, err := uuid.Parse(commentsID)
	if err != nil {
		return nil, errors.New("Gagal format comments ID")
	}

	//ambil user
	authenticatedUserID, exists := ctx.Get("user_id")
	if !exists {
		return nil, errors.New("Unauthorized: Pengguna tidak terautentikasi")
	}

	userIDStr, ok := authenticatedUserID.(string)
	if !ok {
		return nil, errors.New("invalid user id format")
	}

	userUUID, err := uuid.Parse(userIDStr)
	if err != nil {
		return nil, errors.New("invalid user id format: " + err.Error())
	}

	existingKomen, err := s.commentsRepo.GetCommentsByID(commentsUUID)
	if err != nil {
		return nil, err
	}

	//Cek user id created
	if existingKomen.UserID == nil || *existingKomen.UserID != userUUID {
		return nil, errors.New("Forbidden: Anda hanya dapat memperbarui komentar Anda sendiri")
	}

	var commentsreq model.CommentsRequest
	if err := ctx.ShouldBindJSON(&commentsreq); err != nil {
		return nil, err
	}

	if commentsreq.Content != "" {
		existingKomen.Content = commentsreq.Content
	}

	existingKomen.UpdatedAt = time.Now()

	if err := s.commentsRepo.UpdateComments(existingKomen); err != nil {
		return nil, err
	}

	return s.convertToResponse(existingKomen), nil
}

func (s *commentsService) DeleteComments(ctx *gin.Context) error {
	commentsID := ctx.Param("comments_id")
	commentsUUID, err := uuid.Parse(commentsID)
	if err != nil {
		return errors.New("Gagal format task ID")
	}

	authenticatedUserID, exists := ctx.Get("user_id")
	if !exists {
		return errors.New("Unauthorized: Pengguna tidak terautentikasi")
	}

	userIDStr, ok := authenticatedUserID.(string)
	if !ok {
		return errors.New("Gagal user format")
	}

	userUUID, err := uuid.Parse(userIDStr)
	if err != nil {
		return errors.New("invalid user id format: " + err.Error())
	}

	existingKomen, err := s.commentsRepo.GetCommentsByID(commentsUUID)
	if err != nil {
		return err
	}

	if existingKomen.UserID == nil || *existingKomen.UserID != userUUID {
		return errors.New("Forbidden: Anda hanya dapat memperbarui komentar Anda sendiri")
	}

	return s.commentsRepo.DeleteComments(commentsUUID)
}

func (s *commentsService) convertToResponse(comments *model.Comments) *model.CommentsResponse {
	return &model.CommentsResponse{
		ID:        comments.ID,
		TaskID:    comments.TaskID,
		UserID:    comments.UserID,
		Content:   comments.Content,
		CreatedAt: comments.CreatedAt,
		UpdatedAt: comments.UpdatedAt,
		Users:     comments.Users,
	}
}
