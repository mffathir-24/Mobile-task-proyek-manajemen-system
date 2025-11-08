package serviceroute

import (
	"database/sql"
	"fmt"
	projectrepo "gintugas/modules/components/Project/repository"
	projectservice "gintugas/modules/components/Project/service"
	"net/http"

	"github.com/gin-gonic/gin"
)

// CreateProjectRouter godoc
// @Summary Buat project baru
// @Description Membuat project baru (hanya admin/manager)
// @Tags projects
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param input body map[string]interface{} true "Data project"
// @Success 201 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Router /api/project [post]
func CreateProjectRouter(db *sql.DB) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		var (
			projekRepo = projectrepo.NewRepository(db)
			projekSrv  = projectservice.NewService(projekRepo)
		)

		Project, err := projekSrv.CreateProjekService(ctx)
		if err != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{
				"error": err.Error(),
			})
			return
		}

		ctx.JSON(http.StatusCreated, gin.H{
			"message": fmt.Sprintf("Data projek berhasil ditambahkan"),
			"Project": Project,
		})
	}
}

// GetAllProjektRouter godoc
// @Summary Get semua projects
// @Description Mendapatkan daftar semua projects (hanya admin/manager)
// @Tags projects
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Router /api/project [get]
func GetAllProjektRouter(db *sql.DB) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		var (
			projekRepo = projectrepo.NewRepository(db)
			projekSrv  = projectservice.NewService(projekRepo)
		)

		Project, err := projekSrv.GetAllProjekService(ctx)
		if err != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{
				"error": err.Error(),
			})
			return
		}

		ctx.JSON(http.StatusOK, gin.H{
			"message": fmt.Sprintf("successfully get all Project data"),
			"Project": Project,
		})
	}
}

// GetProjectRouter godoc
// @Summary Get project by ID
// @Description Mendapatkan detail project berdasarkan ID (hanya admin/manager)
// @Tags projects
// @Produce json
// @Security BearerAuth
// @Param id path string true "Project ID"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Router /api/project/{id} [get]
func GetProjectRouter(db *sql.DB) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		var (
			projekRepo = projectrepo.NewRepository(db)
			projekSrv  = projectservice.NewService(projekRepo)
		)

		Project, err := projekSrv.GetProjekService(ctx)
		if err != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{
				"error": err.Error(),
			})
			return
		}

		ctx.JSON(http.StatusOK, gin.H{
			"message": fmt.Sprintf("successfully get Project data"),
			"Project": Project,
		})
	}
}

// UpdateProjectRouter godoc
// @Summary Update project
// @Description Update data project (hanya admin/manager)
// @Tags projects
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path string true "Project ID"
// @Param input body map[string]interface{} true "Data project"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Router /api/project/{id} [put]
func UpdateProjectRouter(db *sql.DB) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		var (
			projekRepo = projectrepo.NewRepository(db)
			projekSrv  = projectservice.NewService(projekRepo)
		)

		Project, err := projekSrv.UpdateProjekService(ctx)
		if err != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{
				"error": err.Error(),
			})
			return
		}

		ctx.JSON(http.StatusOK, gin.H{
			"message": fmt.Sprintf("Data Project Berhasil di Update"),
			"Project": Project,
		})
	}
}

// DeleteProjectRouter godoc
// @Summary Delete project
// @Description Hapus project (hanya admin/manager)
// @Tags projects
// @Produce json
// @Security BearerAuth
// @Param id path string true "Project ID"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Router /api/project/{id} [delete]
func DeleteProjectRouter(db *sql.DB) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		var (
			projekRepo = projectrepo.NewRepository(db)
			projekSrv  = projectservice.NewService(projekRepo)
		)

		err := projekSrv.DeleteProjekService(ctx)
		if err != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{
				"error": err.Error(),
			})
			return
		}

		ctx.JSON(http.StatusOK, gin.H{
			"message": "Project berhasil dihapus",
		})
	}
}
