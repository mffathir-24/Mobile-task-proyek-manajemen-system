package projectservice

import (
	"errors"
	. "gintugas/modules/components/Project/model"
	. "gintugas/modules/components/Project/repository"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type Service interface {
	CreateProjekService(ctx *gin.Context) (Project, error)
	GetAllProjekService(ctx *gin.Context) (result []Project, err error)
	GetProjekService(ctx *gin.Context) (result Project, err error)
	UpdateProjekService(ctx *gin.Context) (u Project, err error)
	DeleteProjekService(ctx *gin.Context) (err error)
}

type userService struct {
	repository Repository
}

func NewService(repository Repository) Service {
	return &userService{
		repository,
	}
}

func (s *userService) CreateProjekService(ctx *gin.Context) (Project, error) {
	var Projek Project

	if err := ctx.ShouldBindJSON(&Projek); err != nil {
		return Projek, err
	}

	if Projek.Nama == "" {
		return Projek, errors.New("nama projek harus diisi")
	}

	if Projek.Description == "" {
		return Projek, errors.New("deskripsi projek harus diisi")
	}

	uid, exists := ctx.Get("user_id")
	if !exists {
		return Projek, errors.New("unauthorized: user tidak terautentikasi")
	}

	userIDStr, ok := uid.(string)
	if !ok {
		return Projek, errors.New("invalid user id format")
	}

	userUUID, err := uuid.Parse(userIDStr)
	if err != nil {
		return Projek, errors.New("invalid user id format: " + err.Error())
	}

	user, err := s.repository.GetUserByIDRepository(userUUID)
	if err != nil {
		return Projek, errors.New("gagal mengambil data user: " + err.Error())
	}

	Projek.ManagerID = userUUID
	Projek.Manager = user

	result, err := s.repository.CreateProjekRepository(Projek)
	if err != nil {
		return Projek, errors.New("gagal menambahkan projek: " + err.Error())
	}

	return result, nil
}

func (s *userService) GetAllProjekService(ctx *gin.Context) (result []Project, err error) {
	projeks, err := s.repository.GetAllProjekRepository()
	if err != nil {
		return nil, errors.New("gagal mengambil data projek: " + err.Error())
	}

	return projeks, nil
}

func (s *userService) GetProjekService(ctx *gin.Context) (result Project, err error) {
	idStr := ctx.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		return Project{}, errors.New("ID projek tidak valid")
	}

	result, err = s.repository.GetProjekRepository(id)
	if err != nil {
		return Project{}, errors.New("projek tidak ditemukan: " + err.Error())
	}

	return result, nil
}

func (s *userService) UpdateProjekService(ctx *gin.Context) (u Project, err error) {
	idStr := ctx.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		return Project{}, errors.New("ID projek tidak valid")
	}

	currentUserID, exists := ctx.Get("user_id")
	if !exists {
		return Project{}, errors.New("unauthorized: user tidak terautentikasi")
	}

	userIDStr, ok := currentUserID.(string)
	if !ok {
		return Project{}, errors.New("invalid user id format")
	}

	userUUID, err := uuid.Parse(userIDStr)
	if err != nil {
		return Project{}, errors.New("invalid user id format: " + err.Error())
	}

	existingProjek, err := s.repository.GetProjekByIDRepository(id)
	if err != nil {
		return Project{}, errors.New("project tidak ditemukan")
	}

	if existingProjek.ManagerID != userUUID {
		return Project{}, errors.New("forbidden: hanya manager yang bisa update project")
	}

	var projects Project
	if err := ctx.ShouldBindJSON(&projects); err != nil {
		return Project{}, errors.New("data request tidak valid")
	}

	if strings.TrimSpace(projects.Nama) == "" {
		projects.Nama = existingProjek.Nama
	}

	if strings.TrimSpace(projects.Description) == "" {
		projects.Description = existingProjek.Description
	}

	projects.ManagerID = existingProjek.ManagerID

	projects.ID = id

	updatedProject, err := s.repository.UpdateProjekRepository(projects)
	if err != nil {
		return Project{}, err
	}

	manager, err := s.repository.GetUserByIDRepository(updatedProject.ManagerID)
	if err == nil {
		updatedProject.Manager = manager
	}

	return updatedProject, nil
}

func (s *userService) DeleteProjekService(ctx *gin.Context) (err error) {
	idStr := ctx.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		return errors.New("ID Projek tidak valid")
	}

	err = s.repository.DeleteProjekRepository(id)
	if err != nil {
		return err
	}

	return
}
