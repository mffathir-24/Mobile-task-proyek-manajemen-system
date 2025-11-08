package projectservice

import (
	repository "gintugas/modules/components/Project/repository"
	"net/http"

	"github.com/gin-gonic/gin"
)

type ProjectMemberService struct {
	MemberRepo *repository.ProjectMemberRepo
}

func NewProjectMemberService(memberRepo *repository.ProjectMemberRepo) *ProjectMemberService {
	return &ProjectMemberService{MemberRepo: memberRepo}
}

type AddMemberRequest struct {
	UserID string `json:"user_id" binding:"required"`
}

// AddMember godoc
// @Summary Tambah member ke project
// @Description Menambahkan member ke project (hanya admin/manager)
// @Tags projects
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param project_id path string true "Project ID"
// @Param input body AddMemberRequest true "Data member"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /api/projects/{project_id}/members [post]
func (s *ProjectMemberService) AddMember(ctx *gin.Context) {
	projectID := ctx.Param("project_id")

	var req AddMemberRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := s.MemberRepo.AddMember(projectID, req.UserID); err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{"message": "Member added successfully"})
}

// RemoveMember godoc
// @Summary Hapus member dari project
// @Description Menghapus member dari project (hanya admin/manager)
// @Tags projects
// @Produce json
// @Security BearerAuth
// @Param project_id path string true "Project ID"
// @Param user_id path string true "User ID"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /api/projects/{project_id}/members/{user_id} [delete]
func (s *ProjectMemberService) RemoveMember(ctx *gin.Context) {
	projectID := ctx.Param("project_id")
	userID := ctx.Param("user_id")

	if err := s.MemberRepo.RemoveMember(projectID, userID); err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{"message": "Member removed successfully"})
}

// GetProjectMembers godoc
// @Summary Get semua members dalam project
// @Description Mendapatkan daftar semua members dalam project (hanya admin/manager)
// @Tags projects
// @Produce json
// @Security BearerAuth
// @Param project_id path string true "Project ID"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /api/projects/{project_id}/members [get]
func (s *ProjectMemberService) GetProjectMembers(ctx *gin.Context) {
	projectID := ctx.Param("project_id")

	members, err := s.MemberRepo.GetProjectMembers(projectID)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{"members": members})
}
