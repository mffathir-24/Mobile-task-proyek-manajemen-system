package projectmodel

import (
	usermodels "gintugas/modules/components/Auth/model"
	"time"

	"github.com/google/uuid"
)

type Project struct {
	ID          uuid.UUID         `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	Nama        string            `json:"nama" gorm:"column:nama;type:varchar(150);not null"`
	Description string            `json:"deskripsi" gorm:"column:deskripsi;type:text"`
	ManagerID   uuid.UUID         `json:"manager_id" gorm:"column:manager_id;type:uuid"`
	Manager     usermodels.User   `json:"manager,omitempty" gorm:"foreignKey:ManagerID"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
	Members     []usermodels.User `json:"members,omitempty" gorm:"many2many:project_members;"`
}
