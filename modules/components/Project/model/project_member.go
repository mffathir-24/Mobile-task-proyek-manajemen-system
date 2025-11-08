package projectmodel

import . "gintugas/modules/components/Auth/model"

type ProjectMember struct {
	ProjectID string  `json:"project_id" gorm:"type:uuid;primaryKey"`
	UserID    string  `json:"user_id" gorm:"type:uuid;primaryKey"`
	Project   Project `json:"project,omitempty" gorm:"foreignKey:ProjectID"`
	User      User    `json:"user,omitempty" gorm:"foreignKey:UserID"`
}

func (ProjectMember) TableName() string {
	return "project_members"
}
