package services

import (
	"fmt"
	"net/smtp"
	"os"
)

type MailService interface {
	SendTaskAssignmentNotification(to string, taskTitle string, projectName string) error
}

type mailService struct {
	smtpHost     string
	smtpPort     string
	smtpUsername string
	smtpPassword string
	fromEmail    string
}

func NewMailService() MailService {
	return &mailService{
		smtpHost:     os.Getenv("SMTP_HOST"),
		smtpPort:     os.Getenv("SMTP_PORT"),
		smtpUsername: os.Getenv("SMTP_USERNAME"),
		smtpPassword: os.Getenv("SMTP_PASSWORD"),
		fromEmail:    os.Getenv("FROM_EMAIL"),
	}
}

func (s *mailService) SendTaskAssignmentNotification(to string, taskTitle string, projectName string) error {
	auth := smtp.PlainAuth("", s.smtpUsername, s.smtpPassword, s.smtpHost)

	subject := "New Task Assignment"
	body := fmt.Sprintf("You have been assigned to the task '%s' in project '%s'.", taskTitle, projectName)
	message := fmt.Sprintf("To: %s\r\n"+
		"Subject: %s\r\n"+
		"\r\n"+
		"%s\r\n", to, subject, body)

	err := smtp.SendMail(
		s.smtpHost+":"+s.smtpPort,
		auth,
		s.fromEmail,
		[]string{to},
		[]byte(message),
	)

	return err
}
