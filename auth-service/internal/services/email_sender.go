package services

import (
	"fmt"
	"net/smtp"
)

// ✅ EmailSender implements SMTP email sending logic
type EmailSender struct {
	SMTPHost    string
	SMTPPort    string
	SenderEmail string
	SenderUser  string
	SenderPass  string
}

// Constructor
func NewEmailSender(host, port, email, user, pass string) *EmailSender {
	return &EmailSender{
		SMTPHost:    host,
		SMTPPort:    port,
		SenderEmail: email,
		SenderUser:  user,
		SenderPass:  pass,
	}
}

// SendEmail actually sends an email via SMTP
func (s *EmailSender) SendEmail(to, subject, body string) error {
	auth := smtp.PlainAuth("", s.SenderUser, s.SenderPass, s.SMTPHost)

	msg := []byte(fmt.Sprintf(
		"From: %s\r\nTo: %s\r\nSubject: %s\r\n"+
			"MIME-Version: 1.0\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n%s",
		s.SenderEmail, to, subject, body,
	))

	addr := fmt.Sprintf("%s:%s", s.SMTPHost, s.SMTPPort)

	if err := smtp.SendMail(addr, auth, s.SenderEmail, []string{to}, msg); err != nil {
		return fmt.Errorf("failed to send email: %v", err)
	}
	return nil
}
