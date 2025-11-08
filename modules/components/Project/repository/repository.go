package projectrepo

import (
	"database/sql"
	"errors"
	. "gintugas/modules/components/Auth/model"
	. "gintugas/modules/components/Project/model"

	"github.com/google/uuid"
)

type Repository interface {
	GetManagerByProjectRepository(projectID uuid.UUID) (User, error)
	GetUserByIDRepository(userID uuid.UUID) (User, error)
	CreateProjekRepository(projek Project) (Project, error)
	GetAllProjekRepository() (result []Project, err error)
	GetProjekRepository(id uuid.UUID) (Project, error)
	DeleteProjekRepository(id uuid.UUID) (err error)
	UpdateProjekRepository(projek Project) (Project, error)
	GetProjekByIDRepository(id uuid.UUID) (Project, error)
}

type repository struct {
	db *sql.DB
}

func NewRepository(db *sql.DB) Repository {
	return &repository{db: db}
}

func (r *repository) CreateProjekRepository(projek Project) (Project, error) {
	query := `
        INSERT INTO projects (nama, deskripsi, manager_id) 
        VALUES ($1, $2, $3) 
        RETURNING id, created_at, updated_at
    `

	err := r.db.QueryRow(query, projek.Nama, projek.Description, projek.ManagerID).
		Scan(&projek.ID, &projek.CreatedAt, &projek.UpdatedAt)

	if err != nil {
		return Project{}, err
	}

	return projek, nil
}

func (r *repository) GetAllProjekRepository() (result []Project, err error) {
	query := `
		SELECT
			b.id,
			b.nama,
			b.deskripsi,
			b.manager_id,
			b.created_at,
			k.id as manager_user_id,      
			k.username as manager_username,
			k.email as manager_email,
			k.role as manager_role      
		FROM projects b
		LEFT JOIN users k ON b.manager_id = k.id
		ORDER BY b.id`

	rows, err := r.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var projeks []Project
	for rows.Next() {
		var projek Project
		err := rows.Scan(
			&projek.ID,
			&projek.Nama,
			&projek.Description,
			&projek.ManagerID,
			&projek.CreatedAt,
			&projek.Manager.ID,
			&projek.Manager.Username,
			&projek.Manager.Email,
			&projek.Manager.Role,
		)
		if err != nil {
			return nil, err
		}
		projeks = append(projeks, projek)
	}

	return projeks, nil
}

func (r *repository) GetProjekRepository(id uuid.UUID) (Project, error) {
	query := `
        SELECT
            b.id,
            b.nama,
            b.deskripsi,
            b.manager_id,
            b.created_at,
            k.id as manager_user_id,      
            k.username as manager_username,
            k.email as manager_email,
            k.role as manager_role
        FROM projects b
        LEFT JOIN users k ON b.manager_id = k.id
        WHERE b.id = $1`

	var projek Project
	err := r.db.QueryRow(query, id).Scan(
		&projek.ID,
		&projek.Nama,
		&projek.Description,
		&projek.ManagerID,
		&projek.CreatedAt,
		&projek.Manager.ID,
		&projek.Manager.Username,
		&projek.Manager.Email,
		&projek.Manager.Role,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return Project{}, errors.New("projek tidak ditemukan")
		}
		return Project{}, errors.New("gagal mengambil data projek: " + err.Error())
	}

	return projek, nil
}

func (r *repository) GetProjekByIDRepository(id uuid.UUID) (Project, error) {
	query := "SELECT id, nama, deskripsi, manager_id FROM projects WHERE id = $1"

	var project Project
	err := r.db.QueryRow(query, id).Scan(&project.ID, &project.Nama, &project.Description, &project.ManagerID)

	if err != nil {
		if err == sql.ErrNoRows {
			return Project{}, errors.New("projek tidak ditemukan")
		}
		return Project{}, errors.New("gagal mengambil data projek: " + err.Error())
	}

	return project, nil
}

func (r *repository) GetManagerByProjectRepository(projectID uuid.UUID) (User, error) {
	var user User
	query := `SELECT id, username, email, role, created_at, updated_at FROM users WHERE id = $1`

	err := r.db.QueryRow(query, projectID).Scan(
		&user.ID,
		&user.Username,
		&user.Email,
		&user.Role,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err != nil {
		return User{}, err
	}

	return user, nil
}

func (r *repository) GetUserByIDRepository(userID uuid.UUID) (User, error) {
	var user User
	query := `SELECT id, username, email, role, created_at, updated_at FROM users WHERE id = $1`

	err := r.db.QueryRow(query, userID).Scan(
		&user.ID,
		&user.Username,
		&user.Email,
		&user.Role,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err != nil {
		return User{}, err
	}

	return user, nil
}

func (r *repository) UpdateProjekRepository(projk Project) (Project, error) {
	sql := `UPDATE projects 
            SET nama = $1, deskripsi = $2, manager_id = $3, updated_at = NOW() 
            WHERE id = $4 
            RETURNING id, nama, deskripsi, manager_id, created_at, updated_at`

	var updatedProjek Project
	err := r.db.QueryRow(sql, projk.Nama, projk.Description, projk.ManagerID, projk.ID).
		Scan(&updatedProjek.ID,
			&updatedProjek.Nama,
			&updatedProjek.Description,
			&updatedProjek.ManagerID,
			&updatedProjek.CreatedAt,
			&updatedProjek.UpdatedAt)

	if err != nil {
		return Project{}, errors.New("gagal mengupdate projek: " + err.Error())
	}

	return updatedProjek, nil
}

func (r *repository) DeleteProjekRepository(id uuid.UUID) (err error) {

	sql := "DELETE FROM projects WHERE id = $1"

	result, err := r.db.Exec(sql, id)
	if err != nil {
		return errors.New("gagal menghapus projects: " + err.Error())
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return errors.New("gagal memeriksa rows affected: " + err.Error())
	}

	if rowsAffected == 0 {
		return errors.New("projects tidak ditemukan")
	}

	return nil
}
