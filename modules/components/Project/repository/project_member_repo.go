package projectrepo

import (
	models "gintugas/modules/components/Auth/model"
	model "gintugas/modules/components/Project/model"

	"gorm.io/gorm"
)

type ProjectMemberRepo struct {
	DB *gorm.DB
}

func NewProjectMemberRepo(db *gorm.DB) *ProjectMemberRepo {
	return &ProjectMemberRepo{DB: db}
}

func (r *ProjectMemberRepo) AddMember(projectID, userID string) error {
	member := model.ProjectMember{
		ProjectID: projectID,
		UserID:    userID,
	}
	return r.DB.Create(&member).Error
}

func (r *ProjectMemberRepo) RemoveMember(projectID, userID string) error {
	return r.DB.Where("project_id = ? AND user_id = ?", projectID, userID).
		Delete(&model.ProjectMember{}).Error
}

func (r *ProjectMemberRepo) GetProjectMembers(projectID string) ([]models.User, error) {
	var users []models.User

	err := r.DB.Joins("JOIN project_members ON project_members.user_id = users.id").
		Where("project_members.project_id = ?", projectID).
		Find(&users).Error

	return users, err
}

func (r *ProjectMemberRepo) IsProjectMember(projectID, userID string) (bool, error) {
	var count int64
	err := r.DB.Model(&model.ProjectMember{}).
		Where("project_id = ? AND user_id = ?", projectID, userID).
		Count(&count).Error

	return count > 0, err
}

func (r *ProjectMemberRepo) GetUserProjects(userID string) ([]model.Project, error) {
	var projects []model.Project

	err := r.DB.Joins("JOIN project_members ON project_members.project_id = projects.id").
		Where("project_members.user_id = ?", userID).
		Preload("Manager").
		Find(&projects).Error

	return projects, err
}
