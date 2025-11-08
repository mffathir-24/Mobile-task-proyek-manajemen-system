package service

import (
	"errors"
	"fmt"
	taskmodel "gintugas/modules/components/Tasks/model"
	attachmentmodel "gintugas/modules/components/attachments/models"
	attachmentrepository "gintugas/modules/components/attachments/repository"
	"mime/multipart"
	"os"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type AttachmentService interface {
	UploadAttachment(ctx *gin.Context) (*attachmentmodel.AttachmentResponse, error)
	GetTaskAttachments(ctx *gin.Context) ([]attachmentmodel.AttachmentResponse, error)
	DeleteAttachment(ctx *gin.Context) error
	DownloadAttachment(ctx *gin.Context) (string, error)
}

type attachmentService struct {
	attachmentRepo AttachmentRepository
	uploadPath     string
}

type AttachmentRepository interface {
	CreateAttachment(attachment *attachmentmodel.Attachment) error
	GetAttachmentsByTaskID(taskID uuid.UUID) ([]attachmentmodel.Attachment, error)
	GetAttachmentByID(attachmentID uuid.UUID) (*attachmentmodel.Attachment, error)
	DeleteAttachment(attachmentID uuid.UUID) error
	GetTaskByID(taskID uuid.UUID) (*taskmodel.Task, error)
}

func NewAttachmentService(attachmentRepo attachmentrepository.AttachmentRepository, uploadPath string) AttachmentService {
	// buat jika belum ada folder
	if err := os.MkdirAll(uploadPath, 0755); err != nil {
		fmt.Printf("Warning: gagal membuat folder upload: %v\n", err)
	}

	return &attachmentService{
		attachmentRepo: attachmentRepo,
		uploadPath:     uploadPath,
	}
}

// cek user petugas task
func (s *attachmentService) validateTaskAssignee(ctx *gin.Context, taskID uuid.UUID) error {
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

	task, err := s.attachmentRepo.GetTaskByID(taskID)
	if err != nil {
		return fmt.Errorf("task tidak ditemukan: %v", err)
	}

	//cek task ada petugas
	if task.AssigneeID == nil {
		return errors.New("task ini belum memiliki assignee")
	}

	//cek lagi apakah petugas task
	if *task.AssigneeID != userUUID {
		return errors.New("forbidden: hanya assignee task yang bisa upload attachment")
	}

	return nil
}

func (s *attachmentService) validateFile(file *multipart.FileHeader) error {
	//ukuran file 10mb
	maxSize := int64(10 * 1024 * 1024)
	if file.Size > maxSize {
		return errors.New("ukuran file maksimal 10MB")
	}

	allowedExts := map[string]bool{
		".jpg":  true,
		".jpeg": true,
		".png":  true,
		".gif":  true,
		".pdf":  true,
		".doc":  true,
		".docx": true,
		".xls":  true,
		".xlsx": true,
		".txt":  true,
		".zip":  true,
		".rar":  true,
	}

	ext := strings.ToLower(filepath.Ext(file.Filename))
	if !allowedExts[ext] {
		return errors.New("tipe file tidak diizinkan. File yang diizinkan: jpg, jpeg, png, gif, pdf, doc, docx, xls, xlsx, txt, zip, rar")
	}

	return nil
}

func (s *attachmentService) UploadAttachment(ctx *gin.Context) (*attachmentmodel.AttachmentResponse, error) {
	taskID := ctx.Param("task_id")
	taskUUID, err := uuid.Parse(taskID)
	if err != nil {
		return nil, errors.New("gagal format task ID")
	}

	//cek cuma petugas yang bisa upload
	if err := s.validateTaskAssignee(ctx, taskUUID); err != nil {
		return nil, err
	}

	//ambil form
	file, err := ctx.FormFile("file")
	if err != nil {
		return nil, errors.New("gagal mengambil file: " + err.Error())
	}

	//cek file
	if err := s.validateFile(file); err != nil {
		return nil, err
	}

	//generate nama
	ext := filepath.Ext(file.Filename)
	fileName := fmt.Sprintf("%s%s", uuid.New().String(), ext)
	filePath := filepath.Join(s.uploadPath, fileName)

	//simpan file
	if err := ctx.SaveUploadedFile(file, filePath); err != nil {
		return nil, errors.New("gagal menyimpan file: " + err.Error())
	}

	userIDStr, _ := ctx.Get("user_id")
	userUUID, _ := uuid.Parse(userIDStr.(string))

	attachment := &attachmentmodel.Attachment{
		TaskID:     taskUUID,
		FilePath:   filePath,
		FileName:   file.Filename,
		FileSize:   file.Size,
		MimeType:   file.Header.Get("Content-Type"),
		UploadedBy: userUUID,
	}

	if err := s.attachmentRepo.CreateAttachment(attachment); err != nil {
		//hapus file jika gagal ke db
		os.Remove(filePath)
		return nil, errors.New("gagal menyimpan data attachment: " + err.Error())
	}

	return s.convertToResponse(attachment), nil
}

func (s *attachmentService) GetTaskAttachments(ctx *gin.Context) ([]attachmentmodel.AttachmentResponse, error) {
	taskID := ctx.Param("task_id")
	taskUUID, err := uuid.Parse(taskID)
	if err != nil {
		return nil, errors.New("gagal format task ID")
	}

	attachments, err := s.attachmentRepo.GetAttachmentsByTaskID(taskUUID)
	if err != nil {
		return nil, err
	}

	var response []attachmentmodel.AttachmentResponse
	for _, attachment := range attachments {
		response = append(response, *s.convertToResponse(&attachment))
	}

	return response, nil
}

func (s *attachmentService) DeleteAttachment(ctx *gin.Context) error {
	attachmentID := ctx.Param("attachment_id")
	attachmentUUID, err := uuid.Parse(attachmentID)
	if err != nil {
		return errors.New("gagal format attachment ID")
	}

	attachment, err := s.attachmentRepo.GetAttachmentByID(attachmentUUID)
	if err != nil {
		return errors.New("attachment tidak ditemukan")
	}

	if err := s.validateTaskAssignee(ctx, attachment.TaskID); err != nil {
		return err
	}

	if err := os.Remove(attachment.FilePath); err != nil {
		fmt.Printf("Warning: gagal menghapus file fisik: %v\n", err)
	}

	return s.attachmentRepo.DeleteAttachment(attachmentUUID)
}

func (s *attachmentService) DownloadAttachment(ctx *gin.Context) (string, error) {
	attachmentID := ctx.Param("attachment_id")
	attachmentUUID, err := uuid.Parse(attachmentID)
	if err != nil {
		return "", errors.New("gagal format attachment ID")
	}

	//get detail attachment
	attachment, err := s.attachmentRepo.GetAttachmentByID(attachmentUUID)
	if err != nil {
		return "", errors.New("attachment tidak ditemukan")
	}

	//cek file ada
	if _, err := os.Stat(attachment.FilePath); os.IsNotExist(err) {
		return "", errors.New("file tidak ditemukan di server")
	}

	return attachment.FilePath, nil
}

func (s *attachmentService) convertToResponse(attachment *attachmentmodel.Attachment) *attachmentmodel.AttachmentResponse {
	return &attachmentmodel.AttachmentResponse{
		ID:         attachment.ID,
		TaskID:     attachment.TaskID,
		FilePath:   attachment.FilePath,
		FileName:   attachment.FileName,
		FileSize:   attachment.FileSize,
		MimeType:   attachment.MimeType,
		UploadedBy: attachment.UploadedBy,
		CreatedAt:  attachment.CreatedAt,
		Uploader:   attachment.Uploader,
	}
}
